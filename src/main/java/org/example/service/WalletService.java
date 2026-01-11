package org.example.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.entity.*;
import org.example.enums.CredentialsType;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.integration.IPFSIntegration;
import org.example.repository.*;
import org.example.security.CryptographyService;
import org.example.security.CitizenUserJwtService;
import org.example.utils.HashUtil;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional
public class WalletService {

    private final HyperledgerService hyperledgerService;
    private final OtpService otpService;
    private final MailService mailService;
    private final CryptographyService cryptoService;
    private final WalletRepository walletRepository;
    private final CitizenUserRepository citizenUserRepository;
    private final PublicKeyRepository publicKeyRepository;
    private final DIDDocumentRepository didDocumentRepository;
    private final WalletVerifiableCredentialRepository walletVerifiableCredentialRepository;
    private final VerifiableCredentialRepository verifiableCredentialRepository;
    private final PresentationRequestRepository presentationRequestRepository;
    private final StringRedisTemplate redisTemplate;
    private final CitizenUserJwtService citizenUserJwtService;
    private final IPFSIntegration ipfsIntegration;
    private final DeepfakeDetectionService deepfakeDetectionService;
    private final DeepfakeDetectionLogRepository deepfakeDetectionLogRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public WalletService(
            HyperledgerService hyperledgerService,
            OtpService otpService, MailService mailService,
            CryptographyService cryptoService,
            WalletRepository walletRepository,
            CitizenUserRepository citizenUserRepository,
            PublicKeyRepository publicKeyRepository,
            DIDDocumentRepository didDocumentRepository,
            WalletVerifiableCredentialRepository walletVerifiableCredentialRepository,
            VerifiableCredentialRepository verifiableCredentialRepository,
            PresentationRequestRepository presentationRequestRepository,
            StringRedisTemplate redisTemplate,
            CitizenUserJwtService citizenUserJwtService,
            IPFSIntegration ipfsIntegration,
            DeepfakeDetectionService deepfakeDetectionService,
            DeepfakeDetectionLogRepository deepfakeDetectionLogRepository) {
        this.hyperledgerService = hyperledgerService;
        this.otpService = otpService;
        this.mailService = mailService;
        this.cryptoService = cryptoService;
        this.walletRepository = walletRepository;
        this.citizenUserRepository = citizenUserRepository;
        this.publicKeyRepository = publicKeyRepository;
        this.didDocumentRepository = didDocumentRepository;
        this.walletVerifiableCredentialRepository = walletVerifiableCredentialRepository;
        this.verifiableCredentialRepository = verifiableCredentialRepository;
        this.presentationRequestRepository = presentationRequestRepository;
        this.redisTemplate = redisTemplate;
        this.citizenUserJwtService = citizenUserJwtService;
        this.ipfsIntegration = ipfsIntegration;
        this.deepfakeDetectionService = deepfakeDetectionService;
        this.deepfakeDetectionLogRepository = deepfakeDetectionLogRepository;
    }

    /**
     * Initiate wallet creation by validating DID and sending OTP
     */
    public String initiateWalletCreation(String did) {
        // Verify DID exist on blockchain
        CitizenUser citizenUser = citizenUserRepository.findByAnyHash(null, null, HashUtil.sha256(did));
        if (citizenUser == null || !"ACTIVE".equalsIgnoreCase(String.valueOf(citizenUser.getStatus()))) {
            throw new SludiException(ErrorCodes.INVALID_DID, "DID not found or user is inactive");
        }

        // Get email from DID document
        String email = citizenUser.getEmail();
        if (email == null || email.isBlank()) {
            throw new SludiException(ErrorCodes.INVALID_DID, "No email associated with DID");
        }

        // Generate and send OTP
        OTP otp = otpService.generateOTP(did);
        try {
            mailService.sendOtpEmail(email, citizenUser.getFullName(), otp.getCode());
            return "Did verify and Otp send to:" + email;
        } catch (Exception e) {
            throw new SludiException(ErrorCodes.OTP_SEND_FAILED, "Failed to send OTP", e);
        }
    }

    public boolean verifyOTP(String did, String otp) {
        return otpService.verifyOTP(did, otp);
    }

    /**
     * Create wallet with publicKey
     */
    public Map<String, String> createWallet(String did, String publicKeyStr) {
        try {
            validateWalletCreationInputs(did, publicKeyStr);

            // Check if wallet already exists
            if (walletRepository.existsByDidId(did)) {
                throw new SludiException(ErrorCodes.WALLET_EXISTS, "This user already has a wallet");
            }

            // Get DID document
            DIDDocument didDocument = didDocumentRepository.findById(did)
                    .orElseThrow(() -> new SludiException(ErrorCodes.INVALID_DID, "No DID found for this ID"));

            // Get Citizen user
            CitizenUser user = citizenUserRepository.findByAnyHash(null, null, HashUtil.sha256(did));
            if (user == null) {
                throw new SludiException(ErrorCodes.USER_NOT_FOUND, "User not found for DID: " + did);
            }

            List<PublicKeyDto> publicKeyDtos = getPublicKeyDtos(did, publicKeyStr, didDocument);

            List<Services> services = new ArrayList<>(didDocument.getServices());

            Services walletService = new Services();
            walletService.setId(did + "#wallet");
            walletService.setType("WalletService");
            walletService.setServiceEndpoint("https://api.sludi.com/wallet/" + did);

            services.add(walletService);

            String publicKeysJson = objectMapper.writeValueAsString(publicKeyDtos);
            String servicesJson = objectMapper.writeValueAsString(services);

            // Register public key on blockchain
            hyperledgerService.updateDID(did, publicKeysJson, servicesJson, didDocument.getProof());

            // Save public key in DB
            savePublicKey(publicKeyStr, did, user, didDocument);

            // Create and save wallet
            Wallet wallet = createAndSaveWallet(did, user);

            // Fetch and encrypt VCs
            storeEncryptedVerifiableCredentials(wallet);

            // Return response
            Map<String, String> response = new HashMap<>();
            response.put("walletId", wallet.getId());
            response.put("publicKey", publicKeyStr);
            return response;

        } catch (SludiException e) {
            throw e;
        } catch (Exception e) {
            throw new SludiException(ErrorCodes.WALLET_CREATION_FAILED, e);
        }
    }

    /**
     * Generate challenge (nonce) for wallet login
     */
    public String generateChallenge(String did) {
        CitizenUser user = citizenUserRepository.findByAnyHash(null, null, HashUtil.sha256(did));
        if (user == null || !"ACTIVE".equalsIgnoreCase(user.getStatus().name())) {
            throw new SludiException(ErrorCodes.INVALID_DID, "DID not found or user inactive");
        }

        String nonce = UUID.randomUUID().toString();

        // Save nonce in Redis with short TTL (5 minutes)
        redisTemplate.opsForValue().set("wallet:nonce:" + did, nonce, Duration.ofMinutes(5));

        return nonce;
    }

    /**
     * Verify signed challenge from wallet
     */
    public Map<String, String> verifyChallenge(String did, String signatureStr) {
        CitizenUser user = citizenUserRepository.findByAnyHash(null, null, HashUtil.sha256(did));
        if (user == null || !"ACTIVE".equalsIgnoreCase(user.getStatus().name())) {
            throw new SludiException(ErrorCodes.INVALID_DID, "DID not found or user inactive");
        }

        String nonceKey = "wallet:nonce:" + did;
        String nonce = redisTemplate.opsForValue().get(nonceKey);
        if (nonce == null) {
            throw new SludiException(ErrorCodes.INVALID_NONCE, "Challenge expired or missing");
        }

        Wallet wallet = user.getWallet();
        if (wallet == null) {
            throw new SludiException(ErrorCodes.WALLET_NOT_FOUND, "Wallet not found for DID");
        }

        // Verify signature
        PublicKey publicKey = publicKeyRepository.findByCitizenUser(user);
        boolean valid = cryptoService.verifySignature(nonce, signatureStr, publicKey.getPublicKeyBase58());

        if (!valid) {
            throw new SludiException(ErrorCodes.SIGNATURE_FAILED, "Signature verification failed");
        }

        // Remove nonce after successful verification
        redisTemplate.delete(nonceKey);

        // Issue JWT
        String token = citizenUserJwtService.generateAccessToken(user);
        String refreshToken = citizenUserJwtService.generateRefreshToken(user);

        // Return response
        Map<String, String> response = new HashMap<>();
        response.put("token", token);
        response.put("refreshToken", refreshToken);
        return response;
    }

    /**
     * Retrieve wallet with data
     */
    public WalletDto retrieveWallet(String did) {
        try {
            // Find wallet by DID
            Wallet wallet = walletRepository.findByDidId(did)
                    .orElseThrow(() -> new SludiException(ErrorCodes.WALLET_NOT_FOUND));

            // Get all stored wallet verifiable credentials
            List<WalletVerifiableCredential> walletVCList = walletVerifiableCredentialRepository
                    .findAllByWallet(wallet);

            List<WalletVerifiableCredentialDto> vcDtoList = new ArrayList<>();

            for (WalletVerifiableCredential walletVC : walletVCList) {

                VerifiableCredential vc = walletVC.getVerifiableCredential();
                String decryptedJson = cryptoService.decryptData(walletVC.getEncryptedCredential());

                Object subjectObj = mapSubject(vc.getCredentialType(), decryptedJson);

                ProofData proofData = vc.getProof();
                ProofDataDto proofDto = ProofDataDto.builder()
                        .proofType(proofData.getProofType())
                        .created(proofData.getCreated())
                        .creator(proofData.getCreator())
                        .issuerDid(proofData.getIssuerDid())
                        .signatureValue(proofData.getSignatureValue())
                        .build();

                WalletVerifiableCredentialDto dto = WalletVerifiableCredentialDto.builder()
                        .issuanceDate(vc.getIssuanceDate())
                        .expirationDate(vc.getExpirationDate())
                        .credentialId(vc.getId())
                        .credentialType(vc.getCredentialType())
                        .status(vc.getStatus())
                        .credentialSubject(subjectObj)
                        .proof(proofDto)
                        .blockchainTxId(vc.getBlockchainTxId())
                        .blockNumber(vc.getBlockNumber())
                        .build();

                vcDtoList.add(dto);
            }

            // Update last accessed
            wallet.setLastAccessed(LocalDateTime.now());
            walletRepository.save(wallet);

            return WalletDto.builder()
                    .id(wallet.getId())
                    .citizenUserId(String.valueOf(wallet.getCitizenUser().getId()))
                    .didId(wallet.getDidId())
                    .walletVerifiableCredentials(vcDtoList)
                    .build();

        } catch (SludiException e) {
            throw e;
        } catch (Exception e) {
            throw new SludiException(ErrorCodes.WALLET_RETRIEVAL_FAILED, e);
        }
    }

    public byte[] getProfilePhoto(String cid) {
        byte[] data = ipfsIntegration.retrieveFile(cid);
        if (data == null || data.length == 0) {
            throw new SludiException(ErrorCodes.FILE_READ_ERROR, "No data found for CID: " + cid);
        }
        return data;
    }

    public Map<String, Object> verifyIdentity(
            MultipartFile videoFile,
            String citizenId) throws Exception {

        // Fetch citizen
        CitizenUser citizen = citizenUserRepository.findByAnyHash(null, null, HashUtil.sha256(citizenId));
        if (citizen == null) {
            throw new Exception("Cannot find user!");
        }

        // Get IPFS hash
        String ipfsHash = citizen.getFaceImageIpfsHash();
        if (ipfsHash == null || ipfsHash.isEmpty()) {
            throw new Exception("No face embedding found for this citizen");
        }

        // Retrieve biometric data
        String embeddingBase64 = ipfsIntegration.retrieveBiometricDataAsString(
                ipfsHash,
                citizen.getId().toString());

        embeddingBase64 = embeddingBase64.trim().replaceAll("\\s+", "");

        // Perform face authentication
        FaceVerificationResultDto result = deepfakeDetectionService.faceAuthentication(
                videoFile,
                embeddingBase64);

        // Determine auth result
        String authResult;
        if (result.isDeepfakeDetected()) {
            authResult = "FAILED_DEEPFAKE";
        } else if (!result.isMatch()) {
            authResult = "FAILED_MATCH";
        } else if (result.getLivenessCheckPassed() != null && !result.getLivenessCheckPassed()) {
            authResult = "FAILED_LIVENESS";
        } else {
            authResult = "SUCCESS";
        }

        // Save deepfake detection log
        DeepfakeDetectionLog detectionLog = DeepfakeDetectionLog.builder()
                .citizenId(citizen.getId())
                .citizenDid(citizenId)
                .citizenName(citizen.getFullName())
                .deepfakeDetected(result.isDeepfakeDetected())
                .confidence(result.getConfidence())
                .probabilityFake(result.getProbabilityFake())
                .similarityScore(result.getSimilarity())
                .livenessCheckPassed(result.getLivenessCheckPassed())
                .blinksDetected(result.getBlinksDetected())
                .heatmapBase64(result.getHeatmapBase64())
                .overlayBase64(result.getOverlayBase64())
                .originalImageBase64(result.getOriginalImageBase64())
                .authResult(authResult)
                .processingTimeMs(result.getProcessingTimeMs())
                .thresholdUsed(result.getThresholdUsed())
                .detectedAt(LocalDateTime.now())
                .build();

        deepfakeDetectionLogRepository.save(detectionLog);
        log.info("Saved deepfake detection log for citizen: {} with result: {}", citizenId, authResult);

        Map<String, Object> response = new HashMap<>();
        response.put("verification", result);

        if (result.isMatch() && !result.isDeepfakeDetected()) {
            String token = citizenUserJwtService.generateAccessToken(citizen);
            String refreshToken = citizenUserJwtService.generateRefreshToken(citizen);

            response.put("accessToken", token);
            response.put("refreshToken", refreshToken);
            response.put("status", "AUTH_SUCCESS");
        } else {
            response.put("status", "AUTH_FAILED");
        }

        return response;
    }

    public List<PresentationRequestHistoryDto> getHolderRequestHistory(String holderDid) {
        List<PresentationRequest> requests = presentationRequestRepository.findByHolderDid(holderDid);

        return requests.stream()
                .map(this::toHistoryDTO)
                .toList();
    }

    private static List<PublicKeyDto> getPublicKeyDtos(String did, String publicKeyStr, DIDDocument didDocument) {
        List<PublicKey> updatedPublicKeys = new ArrayList<>(didDocument.getPublicKey());

        List<PublicKeyDto> publicKeyDtos = new ArrayList<>();

        if (!updatedPublicKeys.isEmpty()) {
            for (PublicKey publicKey : updatedPublicKeys) {
                PublicKeyDto dto = new PublicKeyDto();
                dto.setId(publicKey.getId());
                dto.setType(publicKey.getType());
                dto.setPublicKeyBase58(publicKey.getPublicKeyBase58());
                publicKeyDtos.add(dto);
            }
        }

        PublicKeyDto newPublicKey = new PublicKeyDto();
        newPublicKey.setId(did + "#keys-" + (updatedPublicKeys.size() + 1));
        newPublicKey.setType("Ed25519VerificationKey2020");
        newPublicKey.setPublicKeyBase58(publicKeyStr);
        publicKeyDtos.add(newPublicKey);
        return publicKeyDtos;
    }

    private void validateWalletCreationInputs(String did, String publicKeyStr) {
        if (did == null || did.isBlank()) {
            throw new SludiException(ErrorCodes.INVALID_INPUT, "DID cannot be null or empty");
        }
        if (publicKeyStr == null || publicKeyStr.isBlank()) {
            throw new SludiException(ErrorCodes.INVALID_INPUT, "Public key cannot be null or empty");
        }
    }

    private void savePublicKey(String publicKeyStr, String did, CitizenUser user, DIDDocument didDocument) {
        PublicKey publicKey = new PublicKey();
        publicKey.setId(UUID.randomUUID().toString());
        publicKey.setType("RSA");
        publicKey.setController(did);
        publicKey.setPublicKeyBase58(publicKeyStr);
        publicKey.setDidDocument(didDocument);

        publicKey.setCitizenUser(user);
        user.getPublicKeys().add(publicKey);

        user.getPublicKeys().add(publicKey);

        // Save
        citizenUserRepository.save(user);
    }

    private Wallet createAndSaveWallet(String did, CitizenUser user) {
        Wallet wallet = Wallet.builder()
                .id(UUID.randomUUID().toString())
                .didId(did)
                .citizenUser(user)
                .createdAt(LocalDateTime.now())
                .lastAccessed(LocalDateTime.now())
                .status("ACTIVE")
                .build();

        return walletRepository.save(wallet);
    }

    private void storeEncryptedVerifiableCredentials(Wallet wallet) throws Exception {

        List<VerifiableCredential> vcs = verifiableCredentialRepository.getAllBySubjectDid(wallet.getDidId());

        if (vcs == null || vcs.isEmpty()) {
            log.warn("No credentials found for wallet DID: {}. Skipping storage.", wallet.getDidId());
            wallet.setLastAccessed(LocalDateTime.now());
            walletRepository.save(wallet);
            return;
        }

        for (VerifiableCredential vc : vcs) {

            WalletVerifiableCredential walletVerifiableCredential = WalletVerifiableCredential.builder()
                    .encryptedCredential(vc.getCredentialSubjectHash())
                    .verifiableCredential(vc)
                    .addedAt(LocalDateTime.now())
                    .wallet(wallet)
                    .verified(true)
                    .build();

            walletVerifiableCredentialRepository.save(walletVerifiableCredential);
        }
        walletRepository.save(wallet);
    }

    private Object mapSubject(String credentialType, String decryptedJson) throws Exception {
        if (credentialType.equals(CredentialsType.IDENTITY.toString())) {
            return objectMapper.readValue(decryptedJson, CredentialSubject.class);
        } else if (credentialType.equals(CredentialsType.DRIVING_LICENSE.toString())) {
            return objectMapper.readValue(decryptedJson, DrivingLicenseCredentialSubject.class);
        } else {
            throw new SludiException(ErrorCodes.UNKNOWN_CREDENTIAL_TYPE);
        }
    }

    private PresentationRequestHistoryDto toHistoryDTO(PresentationRequest entity) {
        PresentationRequestHistoryDto dto = new PresentationRequestHistoryDto();

        dto.setId(entity.getId());
        dto.setSessionId(entity.getSessionId());
        dto.setRequesterId(entity.getRequesterId());
        dto.setRequesterName(entity.getRequesterName());
        dto.setRequestedAttributes(entity.getRequestedAttributes());
        dto.setPurpose(entity.getPurpose());
        dto.setStatus(entity.getStatus());
        dto.setCreatedAt(entity.getCreatedAt());
        dto.setExpiresAt(entity.getExpiresAt());
        dto.setFulfilledAt(entity.getFulfilledAt());
        dto.setCompletedAt(entity.getCompletedAt());
        dto.setSharedAttributes(entity.getSharedAttributes());
        dto.setIssuedCredentialId(entity.getIssuedCredentialId());
        dto.setErrorMessage(entity.getErrorMessage());

        return dto;
    }
}