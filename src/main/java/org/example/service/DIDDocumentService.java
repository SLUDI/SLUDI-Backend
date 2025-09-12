package org.example.service;

import org.example.dto.*;
import org.example.entity.*;
import org.example.exception.ErrorCodes;
import org.example.repository.*;
import org.example.integration.IPFSIntegration;
import org.example.integration.AIIntegration;
import org.example.security.CryptographyService;
import org.example.exception.SludiException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

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
    private AIIntegration aiIntegration;

    @Autowired
    private CryptographyService cryptographyService;

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
            user = citizenUserRepository.save(user);

            // Create DID on Hyperledger Fabric
            HyperledgerTransactionResult didResult = hyperledgerService.createDID(request.getPersonalInfo().getNic());

            user.setDidId(didResult.getDidId());
            user.setBlockchainTxId(didResult.getTransactionId());
            user.setDidCreationBlockNumber(didResult.getBlockNumber());
            user.setStatus(CitizenUser.UserStatus.ACTIVE);
            user.setUpdatedAt(LocalDateTime.now());

            user = citizenUserRepository.save(user);

            // Log the registration activity
            logUserActivity(user.getId(), "USER_REGISTRATION", "User registered successfully", request.getDeviceInfo());

            // Return success response
            return UserRegistrationResponseDto.builder()
                    .userId(user.getId())
                    .didId(user.getDidId())
                    .status("SUCCESS")
                    .message("User registered successfully")
                    .blockchainTxId(didResult.getTransactionId())
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
     * Update user profile information
     */
    public UserProfileResponseDto updateUserProfile(UUID userId, UserProfileUpdateRequestDto request) {
        try {
            CitizenUser user = citizenUserRepository.findById(userId)
                    .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

            // Validate update permissions
            if (!CitizenUser.UserStatus.ACTIVE.equals(user.getStatus())) {
                throw new SludiException(ErrorCodes.CANNOT_UPDATE_INACTIVE_USER);
            }

            // Store old values for audit
            Map<String, Object> oldValues = createAuditMap(user);

            // Update profile information
            updateUserFields(user, request);

            // Handle new documents upload if provided
            if (request.getNewDocuments() != null && !request.getNewDocuments().isEmpty()) {
                Map<String, String> documentHashes = storeUserDocuments(userId, request.getNewDocuments());
                // Update user with document references (stored as JSON in address_json field for flexibility)
                updateUserDocumentReferences(user, documentHashes);
            }

            // Update DID document on blockchain if keys changed
            if (request.getNewPublicKey() != null) {
                hyperledgerService.updateDID(user.getDidId(), request.getNewPublicKey(), null);
            }

            user.setUpdatedAt(LocalDateTime.now());
            user = citizenUserRepository.save(user);

            // Create audit log
            logUserActivity(userId, "PROFILE_UPDATE", "Profile updated successfully", request.getDeviceInfo());
            createAuditTrail(userId, "update", "user", userId.toString(), oldValues, createAuditMap(user), "Profile update");

            return createUserProfileResponse(user);

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.USER_PROFILE_UPDATE_FAILED, e.getMessage(), e);
        }
    }

    /**
     * Retrieve user profile information
     */
    public UserProfileResponseDto getUserProfile(UUID userId, String requesterDid) {
        try {
            CitizenUser user = citizenUserRepository.findById(userId)
                    .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

            // Check access permissions (simplified - in production, implement proper authorization)
            if (!user.getDidId().equals(requesterDid) && !isAuthorizedVerifier(requesterDid)) {
                throw new SludiException(ErrorCodes.USER_NOT_AUTHORIZED_TO_ACCESS_PROFILE);
            }

            // Log access attempt
            logUserActivity(userId, "PROFILE_ACCESS", "Profile accessed by: " + requesterDid, null);

            return createUserProfileResponse(user);

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.FAILD_TO_RETRIEVE_USER_PROFILE, e.getMessage(), e);
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
            user.setUpdatedAt(LocalDateTime.now());
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

        if (request.getPersonalInfo().getNic().length() != 12) {
            throw new SludiException(ErrorCodes.INVALID_NIC, "Must be 12 characters");
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
                .dateOfBirth(request.getPersonalInfo().getDateOfBirth())
                .gender(request.getPersonalInfo().getGender())
                .nationality(request.getPersonalInfo().getNationality())
                .citizenship(request.getPersonalInfo().getCitizenship())
                .address(address)
                .status(CitizenUser.UserStatus.PENDING)
                .kycStatus(CitizenUser.KYCStatus.NOT_STARTED)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
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

    private CompletableFuture<String> storeProfilePhotoAsync(UUID userId, MultipartFile profilePhoto) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String path = String.format("profile/users/%s/profile_photo.jpg", userId);
                String hash = ipfsIntegration.storeFile(path, profilePhoto.getBytes());
                recordIPFSContent(userId, hash, "profile", "photo", "image/jpeg");
                return hash;
            } catch (Exception e) {
                throw new RuntimeException("Failed to store profile photo: " + e.getMessage(), e);
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

    private UserProfileResponseDto createUserProfileResponse(CitizenUser user) {

        return UserProfileResponseDto.builder()
                .userId(user.getId())
                .didId(user.getDidId())
                .fullName(user.getFullName())
                .nic(user.getNic())
                .email(user.getEmail())
                .phone(user.getPhone())
                .dateOfBirth(user.getDateOfBirth())
                .gender(user.getGender())
                .nationality(user.getNationality())
                .address(convertJsonToAddress(user.getAddress()))
                .status(user.getStatus().toString())
                .kycStatus(user.getKycStatus().toString())
                .profilePhotoHash(user.getProfilePhotoIpfsHash())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .lastLogin(user.getLastLogin())
                .build();
    }

    private AddressDto convertJsonToAddress(Address address) {
        try {
            if (address == null) {
                return AddressDto.builder()
                        .street("")
                        .city("")
                        .state("")
                        .postalCode("")
                        .country("")
                        .district("")
                        .divisionalSecretariat("")
                        .gramaNiladhariDivision("")
                        .build();
            }

            return AddressDto.builder()
                    .street(address.getStreet())
                    .city(address.getCity())
                    .state(address.getState())
                    .postalCode(address.getPostalCode())
                    .country(address.getCountry())
                    .district(address.getDistrict())
                    .divisionalSecretariat(address.getDivisionalSecretariat())
                    .gramaNiladhariDivision(address.getGramaNiladhariDivision())
                    .build();

        } catch (Exception e) {
            throw new SludiException(
                    ErrorCodes.ADDRESS_PARSE_ERROR, e.getMessage(), e
            );
        }
    }

    private String convertAddressToJson(AddressDto address) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(address);
        } catch (Exception e) {
            throw new SludiException(
                    ErrorCodes.ADDRESS_CONVERSION_ERROR, e.getMessage(), e
            );
        }
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

    private Map<String, Object> createAuditMap(CitizenUser user) {
        Map<String, Object> map = new HashMap<>();
        map.put("fullName", user.getFullName());
        map.put("email", user.getEmail());
        map.put("phone", user.getPhone());
        map.put("status", user.getStatus().toString());
        map.put("updatedAt", user.getUpdatedAt());
        return map;
    }

    private void updateUserFields(CitizenUser user, UserProfileUpdateRequestDto request) {
        if (request.getEmail() != null) {
            user.setEmail(request.getEmail());
        }
        if (request.getPhone() != null) {
            user.setPhone(request.getPhone());
        }
        if (request.getAddress() != null) {
            Address newAddress = Address.builder()
                    .street(request.getAddress().getStreet())
                    .city(request.getAddress().getCity())
                    .state(request.getAddress().getState())
                    .postalCode(request.getAddress().getPostalCode())
                    .country("Sri Lanka")
                    .district(request.getAddress().getDistrict())
                    .divisionalSecretariat(request.getAddress().getDivisionalSecretariat())
                    .gramaNiladhariDivision(request.getAddress().getGramaNiladhariDivision())
                    .build();
            user.setAddress(newAddress);
        }
    }

    private Map<String, String> storeUserDocuments(UUID userId, List<MultipartFile> documents) {
        Map<String, String> documentHashes = new HashMap<>();
        for (MultipartFile doc : documents) {
            try {
                String path = String.format("documents/users/%s/%s", userId, doc.getOriginalFilename());
                String hash = ipfsIntegration.storeFile(path, doc.getBytes());
                documentHashes.put(doc.getOriginalFilename(), hash);
                recordIPFSContent(userId, hash, "document", "user_document", doc.getContentType());
            } catch (Exception e) {
                throw new RuntimeException("Failed to store document: " + doc.getOriginalFilename(), e);
            }
        }
        return documentHashes;
    }

    private void updateUserDocumentReferences(CitizenUser user, Map<String, String> documentHashes) {
        try {
            Map<String, Object> documentData = new HashMap<>();
            documentData.put("documents", documentHashes);
            documentData.put("updatedAt", LocalDateTime.now().toString());

            Address currentAddress = user.getAddress();
            if (currentAddress == null) {
                currentAddress = new Address();
            }

            user.setAddress(Address.builder()
                    .street(currentAddress.getStreet())
                    .city(currentAddress.getCity())
                    .state(currentAddress.getState())
                    .postalCode(currentAddress.getPostalCode())
                    .country(currentAddress.getCountry())
                    .district(currentAddress.getDistrict())
                    .divisionalSecretariat(currentAddress.getDivisionalSecretariat())
                    .gramaNiladhariDivision(currentAddress.getGramaNiladhariDivision())
                    .build());

        } catch (Exception e) {
            throw new SludiException(
                    ErrorCodes.DOCUMENT_UPDATE_ERROR, e.getMessage(), e
            );
        }
    }

    private void createAuditTrail(UUID userId, String actionType, String resourceType, String resourceId,
                                  Map<String, Object> oldValues, Map<String, Object> newValues, String reason) {
        // Implementation would create audit trail record
        // This is a placeholder for the audit functionality
    }
}
