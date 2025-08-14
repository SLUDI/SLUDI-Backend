package org.example.service;

import org.example.dto.*;
import org.example.entity.User;
import org.example.entity.AuthenticationLog;
import org.example.entity.IPFSContent;
import org.example.repository.UserRepository;
import org.example.repository.AuthenticationLogRepository;
import org.example.repository.IPFSContentRepository;
import org.example.integration.IPFSService;
import org.example.integration.HyperledgerService;
import org.example.integration.AIService;
import org.example.security.CryptographyService;
import org.example.exception.SludiException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.security.MessageDigest;
import java.util.concurrent.CompletableFuture;

@Service
@Transactional
public class UserRegistrationService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthenticationLogRepository authLogRepository;

    @Autowired
    private IPFSContentRepository ipfsContentRepository;

    @Autowired
    private IPFSService ipfsService;

    @Autowired
    private HyperledgerService hyperledgerService;

    @Autowired
    private AIService aiService;

    @Autowired
    private CryptographyService cryptographyService;

    /**
     * Register a new user with complete identity setup
     * Implements the full flow: PostgreSQL -> IPFS -> Hyperledger Fabric
     */
    public UserRegistrationResponseDto registerUser(UserRegistrationRequestDto request) {
        try {
            // Step 1: Validate input data
            validateRegistrationRequest(request);

            // Step 2: Check if user already exists
            if (userRepository.existsByNic(request.getPersonalInfo().getNic())) {
                throw new SludiException("User with this NIC already exists", "USER_EXISTS");
            }

            if (userRepository.existsByEmail(request.getContactInfo().getEmail())) {
                throw new SludiException("User with this email already exists", "EMAIL_EXISTS");
            }

            // Step 3: AI verification of biometric data
            BiometricVerificationResult biometricResult = verifyBiometricAuthenticity(request.getBiometricData());
            if (!biometricResult.isAuthentic()) {
                throw new SludiException("Biometric verification failed: " + biometricResult.getReason(), "BIOMETRIC_INVALID");
            }

            // Step 4: Create user entity (status: pending)
            User user = createUserEntity(request);
            user = userRepository.save(user);

            // Step 5: Store biometric data in IPFS (parallel execution)
            CompletableFuture<BiometricIPFSHashes> biometricFuture = storeBiometricDataAsync(user.getId(), request.getBiometricData());

            // Step 6: Store profile photo in IPFS (if provided)
            CompletableFuture<String> profilePhotoFuture = null;
            if (request.getProfilePhoto() != null) {
                profilePhotoFuture = storeProfilePhotoAsync(user.getId(), request.getProfilePhoto());
            }

            // Step 7: Wait for IPFS operations to complete
            BiometricIPFSHashes biometricHashes = biometricFuture.get();
            String profilePhotoHash = profilePhotoFuture != null ? profilePhotoFuture.get() : null;

            // Step 8: Create DID on Hyperledger Fabric
            String didId = "did:sludi:" + user.getId().toString();
            HyperledgerTransactionResult didResult = hyperledgerService.registerCitizen(
                    createCitizenRegistration(user, request, biometricHashes)
            );

            // Step 9: Update user with IPFS hashes and blockchain references
            user.setDidId(didId);
            user.setFingerprintIpfsHash(biometricHashes.getFingerprintHash());
            user.setFaceImageIpfsHash(biometricHashes.getFaceImageHash());
            user.setSignatureIpfsHash(biometricHashes.getSignatureHash());
            user.setProfilePhotoIpfsHash(profilePhotoHash);
            user.setBlockchainTxId(didResult.getTransactionId());
            user.setDidCreationBlockNumber(didResult.getBlockNumber());
            user.setStatus(User.UserStatus.ACTIVE);
            user.setUpdatedAt(LocalDateTime.now());

            user = userRepository.save(user);

            // Step 10: Log the registration activity
            logUserActivity(user.getId(), "USER_REGISTRATION", "User registered successfully", request.getDeviceInfo());

            // Step 11: Return success response
            return UserRegistrationResponseDto.builder()
                    .userId(user.getId())
                    .didId(didId)
                    .status("SUCCESS")
                    .message("User registered successfully")
                    .blockchainTxId(didResult.getTransactionId())
                    .build();

        } catch (Exception e) {
            throw new SludiException("User registration failed: " + e.getMessage(), "REGISTRATION_FAILED", e);
        }
    }

    /**
     * Update user profile information
     */
    public UserProfileResponseDto updateUserProfile(UUID userId, UserProfileUpdateRequestDto request) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new SludiException("User not found", "USER_NOT_FOUND"));

            // Validate update permissions
            if (!User.UserStatus.ACTIVE.equals(user.getStatus())) {
                throw new SludiException("Cannot update inactive user profile", "USER_INACTIVE");
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
            user = userRepository.save(user);

            // Create audit log
            logUserActivity(userId, "PROFILE_UPDATE", "Profile updated successfully", request.getDeviceInfo());
            createAuditTrail(userId, "update", "user", userId.toString(), oldValues, createAuditMap(user), "Profile update");

            return createUserProfileResponse(user);

        } catch (Exception e) {
            throw new SludiException("Profile update failed: " + e.getMessage(), "UPDATE_FAILED", e);
        }
    }

    /**
     * Retrieve user profile information
     */
    public UserProfileResponseDto getUserProfile(UUID userId, String requesterDid) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new SludiException("User not found", "USER_NOT_FOUND"));

            // Check access permissions (simplified - in production, implement proper authorization)
            if (!user.getDidId().equals(requesterDid) && !isAuthorizedVerifier(requesterDid)) {
                throw new SludiException("Unauthorized access to user profile", "UNAUTHORIZED");
            }

            // Log access attempt
            logUserActivity(userId, "PROFILE_ACCESS", "Profile accessed by: " + requesterDid, null);

            return createUserProfileResponse(user);

        } catch (Exception e) {
            throw new SludiException("Failed to retrieve user profile: " + e.getMessage(), "RETRIEVAL_FAILED", e);
        }
    }

    /**
     * Authenticate user with biometric data
     */
    public AuthenticationResponseDto authenticateUser(AuthenticationRequestDto request) {
        try {
            // Find user by identifier (email, NIC, or DID)
            User user = findUserByIdentifier(request.getIdentifier());
            if (user == null) {
                logFailedAuthentication(request.getIdentifier(), "USER_NOT_FOUND", request.getDeviceInfo());
                throw new SludiException("Invalid credentials", "AUTH_FAILED");
            }

            // Check user status
            if (!User.UserStatus.ACTIVE.equals(user.getStatus())) {
                logFailedAuthentication(request.getIdentifier(), "USER_INACTIVE", request.getDeviceInfo());
                throw new SludiException("User account is inactive", "USER_INACTIVE");
            }

            // Retrieve stored biometric data from IPFS
            BiometricData storedBiometric = retrieveStoredBiometricData(user);

            // Perform biometric verification with AI deepfake detection
            BiometricMatchResult matchResult = aiService.verifyBiometricMatch(
                    request.getBiometric().getData(),
                    storedBiometric,
                    request.getBiometric().getType()
            );

            if (!matchResult.isMatch()) {
                logFailedAuthentication(user.getDidId(), "BIOMETRIC_MISMATCH", request.getDeviceInfo());
                throw new SludiException("Biometric verification failed", "AUTH_FAILED");
            }

            // Verify on blockchain
            String verificationResult = hyperledgerService.verifyCitizen(
                    user.getDidId(),
                    "did:sludi:system", // System DID as verifier
                    request.getBiometric().getType(),
                    generateBiometricHash(Arrays.toString(request.getBiometric().getData())),
                    generateBiometricHash(Arrays.toString(request.getBiometric().getData()))
            );

            if (!"success".equals(verificationResult)) {
                logFailedAuthentication(user.getDidId(), "BLOCKCHAIN_VERIFICATION_FAILED", request.getDeviceInfo());
                throw new SludiException("Blockchain verification failed", "AUTH_FAILED");
            }

            // Generate JWT token
            String accessToken = cryptographyService.generateAccessToken(user);
            String refreshToken = cryptographyService.generateRefreshToken(user);

            // Update last login
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);

            // Log successful authentication
            logSuccessfulAuthentication(user.getId(), user.getDidId(), request.getBiometric().getType(), request.getDeviceInfo());

            return AuthenticationResponseDto.builder()
                    .userId(user.getId())
                    .didId(user.getDidId())
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .expiresIn(3600) // 1 hour
                    .userProfile(createUserProfileResponse(user))
                    .build();

        } catch (Exception e) {
            throw new SludiException("Authentication failed: " + e.getMessage(), "AUTH_FAILED", e);
        }
    }

    /**
     * Deactivate user account
     */
    public String deactivateUser(UUID userId, String reason) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new SludiException("User not found", "USER_NOT_FOUND"));

            // Deactivate DID on blockchain
            hyperledgerService.deactivateDID(user.getDidId());

            // Update user status
            user.setStatus(User.UserStatus.DEACTIVATED);
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);

            // Log deactivation
            logUserActivity(userId, "USER_DEACTIVATION", "User deactivated: " + reason, null);
            createAuditTrail(userId, "deactivate", "user", userId.toString(),
                    Map.of("status", "ACTIVE"), Map.of("status", "DEACTIVATED"), reason);

            return "User account deactivated successfully";

        } catch (Exception e) {
            throw new SludiException("User deactivation failed: " + e.getMessage(), "DEACTIVATION_FAILED", e);
        }
    }

    // ===================== PRIVATE HELPER METHODS =====================

    private void validateRegistrationRequest(UserRegistrationRequestDto request) {
        if (request.getPersonalInfo() == null || request.getPersonalInfo().getNic() == null) {
            throw new SludiException("Personal information and NIC are required", "INVALID_INPUT");
        }

        if (request.getPersonalInfo().getNic().length() != 12) {
            throw new SludiException("Invalid NIC format. Must be 12 characters", "INVALID_NIC");
        }

        if (request.getBiometricData() == null ||
                request.getBiometricData().getFingerprint() == null ||
                request.getBiometricData().getFaceImage() == null) {
            throw new SludiException("Biometric data (fingerprint and face image) are required", "MISSING_BIOMETRIC");
        }

        if (request.getContactInfo() == null || request.getContactInfo().getEmail() == null) {
            throw new SludiException("Contact information with email is required", "MISSING_CONTACT");
        }
    }

    private BiometricVerificationResult verifyBiometricAuthenticity(BiometricDataDto biometric) {
        // AI deepfake detection for face image
        if (biometric.getFaceImage() != null) {
            AIDetectionResult faceResult = aiService.detectDeepfake(biometric.getFaceImage(), "face");
            if (!faceResult.isAuthentic()) {
                return BiometricVerificationResult.failed("Face image failed deepfake detection");
            }
        }

        // Liveness detection for fingerprint
        if (biometric.getFingerprint() != null) {
            AIDetectionResult fingerprintResult = aiService.performLivenessCheck(biometric.getFingerprint(), "fingerprint");
            if (!fingerprintResult.isAuthentic()) {
                return BiometricVerificationResult.failed("Fingerprint failed liveness detection");
            }
        }

        return BiometricVerificationResult.success();
    }

    private User createUserEntity(UserRegistrationRequestDto request) {
        return User.builder()
                .id(UUID.randomUUID())
                .fullName(request.getPersonalInfo().getFullName())
                .nic(request.getPersonalInfo().getNic())
                .email(request.getContactInfo().getEmail())
                .phone(request.getContactInfo().getPhone())
                .dateOfBirth(request.getPersonalInfo().getDateOfBirth())
                .gender(request.getPersonalInfo().getGender())
                .nationality("Sri Lankan")
                .addressJson(convertAddressToJson(request.getPersonalInfo().getAddress()))
                .status(User.UserStatus.PENDING)
                .kycStatus(User.KYCStatus.NOT_STARTED)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
    }

    private CompletableFuture<BiometricIPFSHashes> storeBiometricDataAsync(UUID userId, BiometricDataDto biometric) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Store fingerprint
                String fingerprintPath = String.format("biometric/users/%s/fingerprint/fingerprint.jpg", userId);
                String fingerprintHash = ipfsService.storeFile(fingerprintPath, biometric.getFingerprint());

                // Store face image
                String facePath = String.format("biometric/users/%s/face/face_image.jpg", userId);
                String faceHash = ipfsService.storeFile(facePath, biometric.getFaceImage());

                // Store signature if provided
                String signatureHash = null;
                if (biometric.getSignature() != null) {
                    String signaturePath = String.format("biometric/users/%s/signature/signature.png", userId);
                    signatureHash = ipfsService.storeFile(signaturePath, biometric.getSignature());
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
                String hash = ipfsService.storeFile(path, profilePhoto.getBytes());
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
                .encryptionAlgorithm("AES-256")
                .uploadedAt(LocalDateTime.now())
                .build();

        ipfsContentRepository.save(content);
    }

    private CitizenRegistrationDto createCitizenRegistration(User user, UserRegistrationRequestDto request, BiometricIPFSHashes hashes) {
        return CitizenRegistrationDto.builder()
                .userId(user.getId().toString())
                .fullName(user.getFullName())
                .nic(user.getNic())
                .publicKeyBase58(request.getPublicKeyBase58())
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
            throw new RuntimeException("Error generating hash", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    private User findUserByIdentifier(String identifier) {
        return userRepository.findByEmailOrNicOrDidId(identifier, identifier, identifier);
    }

    private BiometricData retrieveStoredBiometricData(User user) {
        try {
            byte[] fingerprintData = ipfsService.retrieveFile(user.getFingerprintIpfsHash());
            byte[] faceData = ipfsService.retrieveFile(user.getFaceImageIpfsHash());

            return BiometricData.builder()
                    .fingerprintData(fingerprintData)
                    .faceImageData(faceData)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to retrieve biometric data", e);
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

    private UserProfileResponseDto createUserProfileResponse(User user) {
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
                .address(convertJsonToAddress(user.getAddressJson()))
                .status(user.getStatus().toString())
                .kycStatus(user.getKycStatus().toString())
                .profilePhotoHash(user.getProfilePhotoIpfsHash())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .lastLogin(user.getLastLogin())
                .build();
    }

    private String convertAddressToJson(AddressDto address) {
        // Convert address DTO to JSON string for storage
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(address);
        } catch (Exception e) {
            return "{}";
        }
    }

    private AddressDto convertJsonToAddress(String addressJson) {
        // Convert JSON string back to address DTO
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().readValue(addressJson, AddressDto.class);
        } catch (Exception e) {
            AddressDto addressDto = new AddressDto();
            return addressDto;
        }
    }

    private String convertDeviceInfoToJson(DeviceInfoDto deviceInfo) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(deviceInfo);
        } catch (Exception e) {
            return "{}";
        }
    }

    private boolean isAuthorizedVerifier(String verifierDid) {
        // Implement logic to check if the verifier DID is authorized
        // This could involve checking against a list of approved verifiers
        return verifierDid.startsWith("did:sludi:government") ||
                verifierDid.startsWith("did:sludi:service");
    }

    private Map<String, Object> createAuditMap(User user) {
        Map<String, Object> map = new HashMap<>();
        map.put("fullName", user.getFullName());
        map.put("email", user.getEmail());
        map.put("phone", user.getPhone());
        map.put("status", user.getStatus().toString());
        map.put("updatedAt", user.getUpdatedAt());
        return map;
    }

    private void updateUserFields(User user, UserProfileUpdateRequestDto request) {
        if (request.getEmail() != null) {
            user.setEmail(request.getEmail());
        }
        if (request.getPhone() != null) {
            user.setPhone(request.getPhone());
        }
        if (request.getAddress() != null) {
            user.setAddressJson(convertAddressToJson(request.getAddress()));
        }
    }

    private Map<String, String> storeUserDocuments(UUID userId, List<MultipartFile> documents) {
        Map<String, String> documentHashes = new HashMap<>();
        for (MultipartFile doc : documents) {
            try {
                String path = String.format("documents/users/%s/%s", userId, doc.getOriginalFilename());
                String hash = ipfsService.storeFile(path, doc.getBytes());
                documentHashes.put(doc.getOriginalFilename(), hash);
                recordIPFSContent(userId, hash, "document", "user_document", doc.getContentType());
            } catch (Exception e) {
                throw new RuntimeException("Failed to store document: " + doc.getOriginalFilename(), e);
            }
        }
        return documentHashes;
    }

    private void updateUserDocumentReferences(User user, Map<String, String> documentHashes) {
        // Store document references in the address_json field (or create a separate documents field)
        try {
            String currentAddress = user.getAddressJson();
            Map<String, Object> addressData = new com.fasterxml.jackson.databind.ObjectMapper()
                    .readValue(currentAddress, Map.class);
            addressData.put("documents", documentHashes);
            user.setAddressJson(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(addressData));
        } catch (Exception e) {
            // Handle error appropriately
        }
    }

    private void createAuditTrail(UUID userId, String actionType, String resourceType, String resourceId,
                                  Map<String, Object> oldValues, Map<String, Object> newValues, String reason) {
        // Implementation would create audit trail record
        // This is a placeholder for the audit functionality
    }
}
