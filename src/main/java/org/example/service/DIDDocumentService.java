package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.dto.*;
import org.example.entity.*;
import org.example.enums.ProofPurpose;
import org.example.exception.ErrorCodes;
import org.example.repository.*;
import org.example.integration.IPFSIntegration;
import org.example.integration.AIIntegration;
import org.example.security.CryptographyService;
import org.example.exception.SludiException;

import org.example.utils.DIDIdGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.security.MessageDigest;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

@Service
@Transactional
public class DIDDocumentService {

    private static final Logger LOGGER = Logger.getLogger(DIDDocumentService.class.getName());

    @Autowired
    private CitizenUserRepository citizenUserRepository;

    @Autowired
    private AuthenticationLogRepository authLogRepository;

    @Autowired
    private IPFSContentRepository ipfsContentRepository;

    @Autowired
    private IPFSIntegration ipfsIntegration;

    @Autowired
    private HyperledgerService hyperledgerService;

    @Autowired
    private DigitalSignatureService digitalSignatureService;

    @Autowired
    private AIIntegration aiIntegration;

    @Autowired
    private CryptographyService cryptographyService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Register a new user with complete identity setup
     */
    public UserRegistrationResponseDto registerUser(UserRegistrationRequestDto request) {
        try {
            // Validate input data
            validateRegistrationRequest(request);

            // Check if user already exists
            if (citizenUserRepository.existsByNic(request.getPersonalInfo().getNic())) {
                LOGGER.info("Checking for existing user with NIC: " + request.getPersonalInfo().getNic());
                throw new SludiException(ErrorCodes.USER_EXISTS_WITH_NIC, request.getPersonalInfo().getNic());
            }

            if (citizenUserRepository.existsByEmail(request.getContactInfo().getEmail())) {
                throw new SludiException(ErrorCodes.USER_EXISTS_WITH_EMAIL, request.getContactInfo().getEmail());
            }

            // Create user entity (status: pending)
            CitizenUser user = createUserEntity(request);
            user.setCreatedAt(LocalDateTime.now().toString());
            user = citizenUserRepository.save(user);

            // Convert user entity to JSON string
            String userData = objectMapper.writeValueAsString(user);

            // Create DID ID
            LocalDate dob = request.getPersonalInfo().getDateOfBirth();
            DIDIdGenerator.Gender gender =
                    request.getPersonalInfo().getGender().equalsIgnoreCase("FEMALE")
                            ? DIDIdGenerator.Gender.FEMALE
                            : DIDIdGenerator.Gender.MALE;

            String didId = DIDIdGenerator.generateDID(dob, gender);


            // Create Proof of Data
            ProofData proofData = digitalSignatureService.createProofData(
                    userData,
                    didId,
                    LocalDateTime.now().toString(),
                    ProofPurpose.DID_CREATION.getValue()
            );

            // Create DID on Hyperledger Fabric
            DIDDocumentDto didResult = hyperledgerService.createDID(didId, user.getCreatedAt(), proofData);

            user.setDidId(didResult.getId());
            user.setBlockchainTxId(didResult.getBlockchainTxId());
            user.setDidCreationBlockNumber(didResult.getBlockNumber());
            user.setStatus(CitizenUser.UserStatus.ACTIVE);
            user.setUpdatedAt(LocalDateTime.now().toString());

            user = citizenUserRepository.save(user);

            // Log the registration activity
            logUserActivity(user.getId(), "USER_REGISTRATION", "User registered successfully", request.getDeviceInfo());

            // Return success response
            return UserRegistrationResponseDto.builder()
                    .userId(user.getId())
                    .didId(user.getDidId())
                    .status("SUCCESS")
                    .message("User registered successfully")
                    .blockchainTxId(didResult.getBlockchainTxId())
                    .build();

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.USER_REGISTRATION_FAILED, e);
        }
    }

    /**
     * Check if a citizen user exists by NIC, email, or DID ID
     */
    public boolean isCitizenUserExistsByNic(String nic) {
        return citizenUserRepository.existsByNic(nic);
    }

    public boolean isCitizenUserExistsByEmail(String email) {
        return citizenUserRepository.existsByEmail(email);
    }

    public boolean isCitizenUserExistsByDidId(String didId) {
        return citizenUserRepository.existsByDidId(didId);
    }

    /**
     * Get Citizen User DIDocument
     * This method retrieves the DID document for a user based on their DID ID.
     */
    public DIDDocumentDto getDIDDocument(String didId) {
        try {
            // Check if the DID exist
            if (didId == null || didId.isEmpty()) {
                throw new SludiException(ErrorCodes.DID_NOT_FOUND, "DID ID cannot be null or empty");
            }

            return hyperledgerService.getDIDDocument(didId);

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.FAILED_TO_RETRIEVE_DID_DOCUMENT, e.getMessage(), e);
        }
    }

    public void generateUserKeyPair(String didId) {
        // Check if the DID exist
        if (didId == null || didId.isEmpty()) {
            throw new SludiException(ErrorCodes.DID_NOT_FOUND, "DID ID cannot be null or empty");
        }

        CitizenUser user = citizenUserRepository.findByEmailOrNicOrDidId(null, null, didId);
        if(user==null) {
            throw new SludiException(ErrorCodes.USER_NOT_FOUND);
        }
    }

    /**
     * Deactivate user account
     */
    public String deactivateUser(UUID userId, String reason) {
        try {
            CitizenUser user = citizenUserRepository.findById(userId)
                    .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

            // Deactivate DID on blockchain
            hyperledgerService.deactivateDID(user.getDidId());

            // Update user status
            user.setStatus(CitizenUser.UserStatus.DEACTIVATED);
            user.setUpdatedAt(LocalDateTime.now().toString());
            citizenUserRepository.save(user);

            // Log deactivation
            logUserActivity(userId, "USER_DEACTIVATION", "User deactivated: " + reason, null);
            createAuditTrail(userId, "deactivate", "user", userId.toString(),
                    Map.of("status", "ACTIVE"), Map.of("status", "DEACTIVATED"), reason);

            return "User account deactivated successfully";

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.USER_DEACTIVATION_FAILED, e.getMessage(), e);
        }
    }

    public Map<String, Object> getUserStatistics() {
        try {
            long totalUsers = citizenUserRepository.count();
            long activeUsers = citizenUserRepository.countByStatus(CitizenUser.UserStatus.ACTIVE);
            long inactiveUsers = citizenUserRepository.countByStatus(CitizenUser.UserStatus.INACTIVE);
            long deactivatedUsers = citizenUserRepository.countByStatus(CitizenUser.UserStatus.DEACTIVATED);

            Map<String, Object> stats = new HashMap<>();
            stats.put("totalUsers", totalUsers);
            stats.put("activeUsers", activeUsers);
            stats.put("inactiveUsers", inactiveUsers);
            stats.put("deactivatedUsers", deactivatedUsers);

            return stats;

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.STATISTICS_RETRIEVAL_FAILED, e.getMessage(), e);
        }
    }

    private void validateRegistrationRequest(UserRegistrationRequestDto request) {
        if (request.getPersonalInfo() == null || request.getPersonalInfo().getNic() == null) {
            throw new SludiException(ErrorCodes.INVALID_INPUT, "Personal information and NIC are required");
        }

        String nic = request.getPersonalInfo().getNic();
        if (!nic.matches("\\d{12}") && !nic.matches("\\d{9}[VX]")) {
            throw new SludiException(ErrorCodes.INVALID_NIC, "Invalid Sri Lankan NIC format");
        }

        if (request.getContactInfo() == null || request.getContactInfo().getEmail() == null) {
            throw new SludiException(ErrorCodes.MISSING_CONTACT_EMAIL, "Contact information with email is required");
        }
    }

    private BiometricVerificationResult verifyBiometricAuthenticity(BiometricDataDto biometric) {
        // AI deepfake detection for face image
        if (biometric.getFaceImage() != null) {
            AIDetectionResult faceResult = aiIntegration.detectDeepfake(biometric.getFaceImage(), "face");
            if (!faceResult.isAuthentic()) {
                return BiometricVerificationResult.failed("Face image failed deepfake detection");
            }
        }

        // Liveness detection for fingerprint
        if (biometric.getFingerprint() != null) {
            AIDetectionResult fingerprintResult = aiIntegration.performLivenessCheck(biometric.getFingerprint(), "fingerprint");
            if (!fingerprintResult.isAuthentic()) {
                return BiometricVerificationResult.failed("Fingerprint failed liveness detection");
            }
        }

        return BiometricVerificationResult.success();
    }

    private CitizenUser createUserEntity(UserRegistrationRequestDto request) {
        AddressDto addressDto = request.getPersonalInfo().getAddress();
        Address address = Address.builder()
                .street(addressDto.getStreet())
                .city(addressDto.getCity())
                .district(addressDto.getDistrict())
                .postalCode(addressDto.getPostalCode())
                .divisionalSecretariat(addressDto.getDivisionalSecretariat())
                .gramaNiladhariDivision(addressDto.getGramaNiladhariDivision())
                .state(addressDto.getState())
                .country(addressDto.getCountry())
                .build();

        return CitizenUser.builder()
                .id(UUID.randomUUID())
                .fullName(request.getPersonalInfo().getFullName())
                .nic(request.getPersonalInfo().getNic())
                .email(request.getContactInfo().getEmail())
                .phone(request.getContactInfo().getPhone())
                .dateOfBirth(request.getPersonalInfo().getDateOfBirth().toString())
                .gender(request.getPersonalInfo().getGender())
                .nationality(request.getPersonalInfo().getNationality())
                .citizenship(request.getPersonalInfo().getCitizenship())
                .address(address)
                .status(CitizenUser.UserStatus.PENDING)
                .kycStatus(CitizenUser.KYCStatus.NOT_STARTED)
                .createdAt(LocalDateTime.now().toString())
                .updatedAt(LocalDateTime.now().toString())
                .build();
    }

    private CompletableFuture<BiometricIPFSHashes> storeBiometricDataAsync(UUID userId, BiometricDataDto biometric) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Store fingerprint
                String fingerprintPath = String.format("biometric/users/%s/fingerprint/fingerprint.jpg", userId);
                String fingerprintHash = ipfsIntegration.storeBiometricData(
                        userId.toString(), "fingerprint", biometric.getFingerprint()
                );

                // Store face image
                String facePath = String.format("biometric/users/%s/face/face_image.jpg", userId);
                String faceHash = ipfsIntegration.storeBiometricData(
                        userId.toString(), "face", biometric.getFaceImage()
                );

                // Store signature if provided
                String signatureHash = null;
                if (biometric.getSignature() != null) {
                    String signaturePath = String.format("biometric/users/%s/signature/signature.png", userId);
                    signatureHash = ipfsIntegration.storeBiometricData(
                            userId.toString(), "fingerprint", biometric.getSignature()
                    );
                }

                // Record IPFS content metadata
                recordIPFSContent(userId, fingerprintHash, "biometric", "fingerprint", "image/jpeg");
                recordIPFSContent(userId, faceHash, "biometric", "face", "image/jpeg");
                if (signatureHash != null) {
                    recordIPFSContent(userId, signatureHash, "biometric", "signature", "image/png");
                }

                return BiometricIPFSHashes.builder()
                        .fingerprintHash(fingerprintHash)
                        .faceImageHash(faceHash)
                        .signatureHash(signatureHash)
                        .build();

            } catch (Exception e) {
                throw new RuntimeException("Failed to store biometric data: " + e.getMessage(), e);
            }
        });
    }

    private void recordIPFSContent(UUID userId, String ipfsHash, String category, String subcategory, String mimeType) {
        IPFSContent content = IPFSContent.builder()
                .id(UUID.randomUUID())
                .ipfsHash(ipfsHash)
                .ownerUserId(userId)
                .category(category)
                .subcategory(subcategory)
                .mimeType(mimeType)
                .accessLevel("private")
                .isEncrypted(true)
                .encryptionAlgorithm("SHA-256")
                .uploadedAt(LocalDateTime.now())
                .build();

        ipfsContentRepository.save(content);
    }

    private CitizenRegistrationDto createCitizenRegistration(CitizenUser user, UserRegistrationRequestDto request, BiometricIPFSHashes hashes) {
        return CitizenRegistrationDto.builder()
                .userId(user.getId().toString())
                .fullName(user.getFullName())
                .dateOfBirth(user.getDateOfBirth().toString())
                .nic(user.getNic())
                .fingerprintHash(generateBiometricHash(hashes.getFingerprintHash()))
                .faceImageHash(generateBiometricHash(hashes.getFaceImageHash()))
                .build();
    }

    private String generateBiometricHash(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes("UTF-8"));
            return "sha256:" + bytesToHex(hash);
        } catch (Exception e) {
            throw new SludiException(
                    ErrorCodes.BIOMETRIC_HASH_GENERATION_ERROR, e.getMessage(), e
            );
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    private CitizenUser findUserByIdentifier(String type, String identifier) {
        if(type=="EMAIL") {
            return citizenUserRepository.findByEmailOrNicOrDidId(identifier, null, null);
        } else if(type=="NIC") {
            return citizenUserRepository.findByEmailOrNicOrDidId(null, identifier, null);
        } else if(type=="DID") {
            return citizenUserRepository.findByEmailOrNicOrDidId(null, null, identifier);
        }
        throw new SludiException(ErrorCodes.INVALID_IDENTIFIER_TYPE, "Invalid identifier type: " + type);
    }

    private BiometricData retrieveStoredBiometricData(CitizenUser user) {
        try {
            byte[] fingerprintData = ipfsIntegration.retrieveFile(user.getFingerprintIpfsHash());
            byte[] faceData = ipfsIntegration.retrieveFile(user.getFaceImageIpfsHash());

            return BiometricData.builder()
                    .fingerprintData(fingerprintData)
                    .faceImageData(faceData)
                    .build();
        } catch (Exception e) {
            throw new SludiException(
                    ErrorCodes.BIOMETRIC_RETRIEVAL_ERROR, e.getMessage(), e
            );
        }
    }

    private void logUserActivity(UUID userId, String activityType, String description, DeviceInfoDto deviceInfo) {
        AuthenticationLog log = AuthenticationLog.builder()
                .id(UUID.randomUUID())
                .userId(userId)
                .authType(activityType)
                .result("success")
                .deviceInfo(deviceInfo != null ? convertDeviceInfoToJson(deviceInfo) : null)
                .attemptedAt(LocalDateTime.now())
                .completedAt(LocalDateTime.now())
                .build();

        authLogRepository.save(log);
    }

    private void logSuccessfulAuthentication(UUID userId, String userDid, String authMethod, DeviceInfoDto deviceInfo) {
        AuthenticationLog log = AuthenticationLog.builder()
                .id(UUID.randomUUID())
                .userId(userId)
                .userDid(userDid)
                .authType("biometric")
                .authMethod(authMethod)
                .result("success")
                .deviceInfo(convertDeviceInfoToJson(deviceInfo))
                .attemptedAt(LocalDateTime.now())
                .completedAt(LocalDateTime.now())
                .build();

        authLogRepository.save(log);
    }

    private void logFailedAuthentication(String identifier, String reason, DeviceInfoDto deviceInfo) {
        AuthenticationLog log = AuthenticationLog.builder()
                .id(UUID.randomUUID())
                .userDid(identifier)
                .authType("biometric")
                .result("failed")
                .failureReason(reason)
                .deviceInfo(convertDeviceInfoToJson(deviceInfo))
                .attemptedAt(LocalDateTime.now())
                .build();

        authLogRepository.save(log);
    }

    private String convertDeviceInfoToJson(DeviceInfoDto deviceInfo) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(deviceInfo);
        } catch (Exception e) {
            throw new SludiException(
                    ErrorCodes.DEVICE_INFO_CONVERSION_ERROR, e.getMessage(), e
            );
        }
    }

    private boolean isAuthorizedVerifier(String verifierDid) {
        // Implement logic to check if the verifier DID is authorized
        // This could involve checking against a list of approved verifiers
        return verifierDid.startsWith("did:sludi:government") ||
                verifierDid.startsWith("did:sludi:service");
    }

    private void createAuditTrail(UUID userId, String actionType, String resourceType, String resourceId,
                                  Map<String, Object> oldValues, Map<String, Object> newValues, String reason) {
        // Implementation would create audit trail record
        // This is a placeholder for the audit functionality
    }
}
