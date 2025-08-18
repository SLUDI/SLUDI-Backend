package org.example.service;

import org.example.dto.*;
import org.example.entity.CitizenUser;
import org.example.entity.VerifiableCredential;
import org.example.entity.Wallet;
import org.example.entity.WalletCredential;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.CitizenUserRepository;
import org.example.repository.WalletRepository;
import org.example.security.CryptographyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@Service
public class WalletService {

    private static final Logger LOGGER = Logger.getLogger(WalletService.class.getName());

    @Autowired
    private HyperledgerService hyperledgerService;

    @Autowired
    private OtpService otpService;

    @Autowired
    private CryptographyService cryptoService;

    @Autowired
    private WalletRepository walletRepository;

    @Autowired
    private CitizenUserRepository citizenUserRepository;

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
            otpService.sendOtpEmail(email, otp.getCode());
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
    public String createWallet(String did, String password) {

        try {
            // Generate wallet ID
            String walletId = UUID.randomUUID().toString();

            // Generate
            byte[] salt = cryptoService.generateSalt();
            String saltBase64 = Base64.getEncoder().encodeToString(salt);

            // Generate encryption key from password
            SecretKey masterKey = cryptoService.generateWalletKey(password, salt);

            // Create encrypted wallet credentials
            WalletCredential credentials = WalletCredential.builder()
                    .encryptedKey(CryptographyService.encryptKey(masterKey))
                    .salt(saltBase64)
                    .iterations(10000)
                    .build();

            // Get User
            CitizenUser user = citizenUserRepository.findByEmailOrNicOrDidId(null, null, did);

            // Create wallet entity
            Wallet wallet = Wallet.builder()
                    .id(walletId)
                    .didId(did)
                    .citizenUser(user)
                    .credentials(credentials)
                    .createdAt(LocalDateTime.now())
                    .lastAccessed(LocalDateTime.now())
                    .status("ACTIVE")
                    .build();

            // Get VCs from blockchain
            List<VerifiableCredential> vcs = hyperledgerService.getCredentialsByDID(wallet.getDidId());

            // Encrypt and store each VC
            for (VerifiableCredential vc : vcs) {
                String encryptedVC = CryptographyService.encryptVC(vc, masterKey);
                wallet.addCredential(encryptedVC);
            }

            // Save wallet
            walletRepository.save(wallet);

            return "Create wallet for user" + did;

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

            // Decrypt VCs stored in wallet
            List<String> encryptedVCs = wallet.getEncryptedCredentials();
            List<VerifiableCredential> decryptedVCs = new ArrayList<>();

            for (String encryptedVC : encryptedVCs) {
                VerifiableCredential vc = CryptographyService.decryptVC(encryptedVC, masterKey);
                decryptedVCs.add(vc);
            }

            // Convert decrypted VCs to DTOs
            List<VerifiableCredentialDto> vcDtos = decryptedVCs.stream()
                    .map(this::convertVCToDto)
                    .collect(Collectors.toList());

            // pdate last accessed timestamp
            wallet.setLastAccessed(LocalDateTime.now());
            walletRepository.save(wallet);

            // Build and return WalletDto
            return WalletDto.builder()
                    .id(wallet.getId())
                    .citizenUserId(String.valueOf(wallet.getCitizenUser().getId()))
                    .didId(wallet.getDidId())
                    .decryptedCredentials(vcDtos)
                    .build();

        } catch (SludiException e) {
            // Pass through known exceptions
            throw e;
        } catch (Exception e) {
            // Wrap all other exceptions
            throw new SludiException(ErrorCodes.WALLET_RETRIEVAL_FAILED, e);
        }
    }


    private VerifiableCredentialDto convertVCToDto(VerifiableCredential ivc) {
        // Convert BiometricHashes to DTO
        BiometricHashesDto biometricHashesDto = BiometricHashesDto.builder()
                .fingerprintHash(ivc.getCredentialSubject().getBiometricHashes().getFingerprintHash())
                .faceImageHash(ivc.getCredentialSubject().getBiometricHashes().getFaceImageHash())
                .build();
        // Convert Address to DTO
        AddressDto addressDto = AddressDto.builder()
                .street(ivc.getCredentialSubject().getAddress().getStreet())
                .city(ivc.getCredentialSubject().getAddress().getCity())
                .state(ivc.getCredentialSubject().getAddress().getState())
                .postalCode(ivc.getCredentialSubject().getAddress().getPostalCode())
                .country(ivc.getCredentialSubject().getAddress().getCountry())
                .district(ivc.getCredentialSubject().getAddress().getDistrict())
                .divisionalSecretariat(ivc.getCredentialSubject().getAddress().getDivisionalSecretariat())
                .gramaNiladhariDivision(ivc.getCredentialSubject().getAddress().getGramaNiladhariDivision())
                .build();

        // Convert CredentialSubject to DTO
        CredentialSubjectDto credentialSubjectDto = CredentialSubjectDto.builder()
                .id(ivc.getCredentialSubject().getId())
                .fullName(ivc.getCredentialSubject().getFullName())
                .nic(ivc.getCredentialSubject().getNic())
                .dateOfBirth(ivc.getCredentialSubject().getDateOfBirth())
                .citizenship(ivc.getCredentialSubject().getCitizenship())
                .gender(ivc.getCredentialSubject().getGender())
                .nationality(ivc.getCredentialSubject().getNationality())
                .biometricData(biometricHashesDto)
                .address(addressDto)
                .build();

        // Convert ProofData to DTO
        ProofDataDto proofDto = ProofDataDto.builder()
                .proofType(ivc.getProof().getProofType())
                .created(ivc.getProof().getCreated())
                .creator(ivc.getProof().getCreator())
                .signatureValue(ivc.getProof().getSignatureValue())
                .build();

        // Convert VerifiableCredential to DTO
       return VerifiableCredentialDto.builder()
                .id(ivc.getId())
                .context(ivc.getContext())
                .credentialTypes(ivc.getCredentialTypes())
                .issuer(ivc.getIssuer())
                .issuanceDate(ivc.getIssuanceDate())
                .expirationDate(ivc.getExpirationDate())
                .credentialSubject(credentialSubjectDto)
                .status(ivc.getStatus())
                .proof(proofDto)
                .createdAt(ivc.getCreatedAt())
                .updatedAt(ivc.getUpdatedAt())
                .build();
    }
}