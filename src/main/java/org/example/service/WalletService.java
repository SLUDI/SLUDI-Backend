package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.entity.*;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.*;
import org.example.security.CryptographyService;
import org.example.security.JwtService;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

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
    private final StringRedisTemplate redisTemplate;
    private final JwtService jwtService;

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
            StringRedisTemplate redisTemplate,
            JwtService jwtService
    ) {
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
        this.redisTemplate = redisTemplate;
        this.jwtService = jwtService;
    }

    /**
     * Initiate wallet creation by validating DID and sending OTP
     */
    public String initiateWalletCreation(String did) {
        // Verify DID exist on blockchain
        CitizenUser citizenUser = citizenUserRepository.findByEmailOrNicOrDidId(null, null, did);
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
    public Map<String, String> createWallet(String did, String password, String publicKeyStr) {
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
            CitizenUser user = citizenUserRepository.findByEmailOrNicOrDidId(null, null, did);
            if (user == null) {
                throw new SludiException(ErrorCodes.USER_NOT_FOUND, "User not found for DID: " + did);
            }

            // Register public key on blockchain
            hyperledgerService.updateDID(did, publicKeyStr, "api/wallet/create");

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
        CitizenUser user = citizenUserRepository.findByEmailOrNicOrDidId(null, null, did);
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
        CitizenUser user = citizenUserRepository.findByEmailOrNicOrDidId(null, null, did);
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
        boolean valid = cryptoService.verifySignature(nonce, signatureStr, publicKey.getPublicKeyStr());

        if (!valid) {
            throw new SludiException(ErrorCodes.SIGNATURE_FAILED, "Signature verification failed");
        }

        // Remove nonce after successful verification
        redisTemplate.delete(nonceKey);

        // Issue JWT
        String token = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

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

            // Get All Wallet VerifiableCredential
            List<WalletVerifiableCredential> walletVerifiableCredentialList = walletVerifiableCredentialRepository.findAllByWallet(wallet);

            // Decrypt VCs in stores wallet
            List<WalletVerifiableCredentialDto> walletVerifiableCredentialDtos = new ArrayList<>();

            for (WalletVerifiableCredential walletVerifiableCredential : walletVerifiableCredentialList) {
                String credentialSubjectJson = cryptoService.decryptData(walletVerifiableCredential.getEncryptedCredential());
                CredentialSubject credentialSubject = objectMapper.readValue(credentialSubjectJson, CredentialSubject.class);

                ProofData proofData = walletVerifiableCredential.getVerifiableCredential().getProof();
                ProofDataDto proofDataDto = ProofDataDto.builder()
                        .proofType(proofData.getProofType())
                        .created(proofData.getCreated())
                        .creator(proofData.getCreator())
                        .issuerDid(proofData.getIssuerDid())
                        .signatureValue(proofData.getSignatureValue())
                        .build();

                WalletVerifiableCredentialDto walletVerifiableCredentialDto = WalletVerifiableCredentialDto.builder()
                        .issuanceDate(walletVerifiableCredential.getVerifiableCredential().getIssuanceDate())
                        .expirationDate(walletVerifiableCredential.getVerifiableCredential().getExpirationDate())
                        .status(walletVerifiableCredential.getVerifiableCredential().getStatus())
                        .credentialSubject(credentialSubject)
                        .proof(proofDataDto)
                        .blockchainTxId(walletVerifiableCredential.getVerifiableCredential().getBlockchainTxId())
                        .blockNumber(walletVerifiableCredential.getVerifiableCredential().getBlockNumber())
                        .build();

                walletVerifiableCredentialDtos.add(walletVerifiableCredentialDto);
            }

            // pdate last accessed timestamp
            wallet.setLastAccessed(LocalDateTime.now());
            walletRepository.save(wallet);

            // Build and return WalletDto
            return WalletDto.builder()
                    .id(wallet.getId())
                    .citizenUserId(String.valueOf(wallet.getCitizenUser().getId()))
                    .walletVerifiableCredentials(walletVerifiableCredentialDtos)
                    .didId(wallet.getDidId())
                    .build();

        } catch (SludiException e) {
            // Pass through known exceptions
            throw e;
        } catch (Exception e) {
            // Wrap all other exceptions
            throw new SludiException(ErrorCodes.WALLET_RETRIEVAL_FAILED, e);
        }
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
        publicKey.setPublicKeyStr(publicKeyStr);
        publicKey.setCitizenUser(user);
        publicKey.setDidDocument(didDocument);

        publicKeyRepository.save(publicKey);
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

}