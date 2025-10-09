package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.entity.*;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.*;
import org.example.security.CryptographyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@Service
@Transactional
public class WalletService {

    @Autowired
    private HyperledgerService hyperledgerService;

    @Autowired
    private OtpService otpService;

    @Autowired
    private MailService mailService;

    @Autowired
    private CryptographyService cryptoService;

    @Autowired
    private WalletRepository walletRepository;

    @Autowired
    private CitizenUserRepository citizenUserRepository;

    @Autowired
    private PublicKeyRepository publicKeyRepository;

    @Autowired
    private DIDDocumentRepository didDocumentRepository;

    @Autowired
    private WalletVerifiableCredentialRepository walletVerifiableCredentialRepository;

    @Autowired
    private VerifiableCredentialRepository verifiableCredentialRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

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
     * Create wallet with password
     */
    public Map<String, String> createWallet(String did, String password, String publicKeyStr) {
        try {
            validateWalletCreationInputs(did, password, publicKeyStr);

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

            // Create wallet credentials
            WalletCredential credentials = createWalletCredentials(password);

            // Save public key in DB
            savePublicKey(publicKeyStr, did, user, didDocument);

            // Create and save wallet
            Wallet wallet = createAndSaveWallet(did, user, credentials);

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

    public WalletDto retrieveWallet(String did, String password) {
        try {
            // Find wallet by DID
            Wallet wallet = walletRepository.findByDidId(did)
                    .orElseThrow(() -> new SludiException(ErrorCodes.WALLET_NOT_FOUND));

            WalletCredential credentials = wallet.getCredentials();

            // Decode salt properly (Base64) instead of using
            byte[] saltBytes = Base64.getDecoder().decode(credentials.getSalt());

            // Reconstruct master key from password + salt
            SecretKey masterKey = cryptoService.generateWalletKey(password, saltBytes);

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

    private void validateWalletCreationInputs(String did, String password, String publicKeyStr) {
        if (did == null || did.isBlank()) {
            throw new SludiException(ErrorCodes.INVALID_INPUT, "DID cannot be null or empty");
        }
        if (password == null || password.isBlank()) {
            throw new SludiException(ErrorCodes.INVALID_INPUT, "Password cannot be null or empty");
        }
        if (publicKeyStr == null || publicKeyStr.isBlank()) {
            throw new SludiException(ErrorCodes.INVALID_INPUT, "Public key cannot be null or empty");
        }
    }

    private WalletCredential createWalletCredentials(String password) throws Exception {
        byte[] salt = cryptoService.generateSalt();
        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        SecretKey masterKey = cryptoService.generateWalletKey(password, salt);

        return WalletCredential.builder()
                .encryptedKey(CryptographyService.encryptKey(masterKey))
                .salt(saltBase64)
                .iterations(10000)
                .build();
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

    private Wallet createAndSaveWallet(String did, CitizenUser user, WalletCredential credentials) {
        Wallet wallet = Wallet.builder()
                .id(UUID.randomUUID().toString())
                .didId(did)
                .citizenUser(user)
                .credentials(credentials)
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