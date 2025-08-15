package org.example.service;

import org.example.dto.*;
import org.example.entity.Address;
import org.example.entity.CitizenUser;
import org.example.entity.AuthenticationLog;
import org.example.entity.IPFSContent;
import org.example.exception.ErrorCodes;
import org.example.repository.CitizenUserRepository;
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
    private CitizenUserRepository citizenUserRepository;

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
            // Validate input data
            validateRegistrationRequest(request);

            // Check if user already exists
            if (citizenUserRepository.existsByNic(request.getPersonalInfo().getNic())) {
                throw new SludiException(ErrorCodes.USER_EXISTS_WITH_NIC, request.getPersonalInfo().getNic());
            }

            if (citizenUserRepository.existsByEmail(request.getContactInfo().getEmail())) {
                throw new SludiException(ErrorCodes.USER_EXISTS_WITH_EMAIL, request.getContactInfo().getEmail());
            }

            // verification of biometric data
            BiometricVerificationResult biometricResult = verifyBiometricAuthenticity(request.getBiometricData());
            if (!biometricResult.isAuthentic()) {
                throw new SludiException(ErrorCodes.BIOMETRIC_INVALID, biometricResult.getReason());
            }

            // Create user entity (status: pending)
            CitizenUser user = createUserEntity(request);
            user = citizenUserRepository.save(user);

            // Store biometric data in IPFS (parallel execution)
            CompletableFuture<BiometricIPFSHashes> biometricFuture = storeBiometricDataAsync(user.getId(), request.getBiometricData());

            // Store profile photo in IPFS (if provided)
            CompletableFuture<String> profilePhotoFuture = null;
            if (request.getProfilePhoto() != null) {
                profilePhotoFuture = storeProfilePhotoAsync(user.getId(), request.getProfilePhoto());
            }

            // Wait for IPFS operations to complete
            BiometricIPFSHashes biometricHashes = biometricFuture.get();
            String profilePhotoHash = profilePhotoFuture != null ? profilePhotoFuture.get() : null;

            // Create DID on Hyperledger Fabric
            String didId = "did:sludi:" + user.getId().toString();
            HyperledgerTransactionResult didResult = hyperledgerService.registerCitizen(
                    createCitizenRegistration(user, request, biometricHashes)
            );

            // Update user with IPFS hashes and blockchain references
            user.setDidId(didId);
            user.setFingerprintIpfsHash(biometricHashes.getFingerprintHash());
            user.setFaceImageIpfsHash(biometricHashes.getFaceImageHash());
            user.setSignatureIpfsHash(biometricHashes.getSignatureHash());
            user.setProfilePhotoIpfsHash(profilePhotoHash);
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
                    .didId(didId)
                    .status("SUCCESS")
                    .message("User registered successfully")
                    .blockchainTxId(didResult.getTransactionId())
                    .build();

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.USER_REGISTRATION_FAILED, e);
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
     * Authenticate user with biometric data
     */
    public AuthenticationResponseDto authenticateUser(AuthenticationRequestDto request) {
        try {
            // Find user by identifier (email, NIC, or DID)
            CitizenUser user = findUserByIdentifier(request.getIdentifier());
            if (user == null) {
                logFailedAuthentication(request.getIdentifier(), "USER_NOT_FOUND", request.getDeviceInfo());
                throw new SludiException(ErrorCodes.INVALID_CREDENTIALS);
            }

            // Check user status
            if (!CitizenUser.UserStatus.ACTIVE.equals(user.getStatus())) {
                logFailedAuthentication(request.getIdentifier(), "USER_INACTIVE", request.getDeviceInfo());
                throw new SludiException(ErrorCodes.USER_INACTIVE);
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
                throw new SludiException(ErrorCodes.BIOMETRIC_MISMATCH);
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
                throw new SludiException(ErrorCodes.BIOMETRIC_VERIFICATION_FAILED);
            }

            // Generate JWT token
            String accessToken = cryptographyService.generateAccessToken(user);
            String refreshToken = cryptographyService.generateRefreshToken(user);

            // Update last login
            user.setLastLogin(LocalDateTime.now());
            citizenUserRepository.save(user);

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
            throw new SludiException(ErrorCodes.AUTH_FAILED, e.getMessage(), e);
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

    private void validateRegistrationRequest(UserRegistrationRequestDto request) {
        if (request.getPersonalInfo() == null || request.getPersonalInfo().getNic() == null) {
            throw new SludiException(ErrorCodes.INVALID_INPUT, "Personal information and NIC are required");
        }

        if (request.getPersonalInfo().getNic().length() != 12) {
            throw new SludiException(ErrorCodes.INVALID_NIC, "Must be 12 characters");
        }

        if (request.getBiometricData() == null ||
                request.getBiometricData().getFingerprint() == null ||
                request.getBiometricData().getFaceImage() == null) {
            throw new SludiException(ErrorCodes.MISSING_BIOMETRIC_DATA, "fingerprint and face image are required");
        }

        if (request.getContactInfo() == null || request.getContactInfo().getEmail() == null) {
            throw new SludiException(ErrorCodes.MISSING_CONTACT_EMAIL, "Contact information with email is required");
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

    private CitizenUser createUserEntity(UserRegistrationRequestDto request) {
        AddressDto addressDto = request.getPersonalInfo().getAddress();
        Address address = Address.builder()
                .street(addressDto.getStreet())
                .city(addressDto.getCity())
                .state(addressDto.getState())
                .postalCode(addressDto.getPostalCode())
                .country("Sri Lanka")
                .district(addressDto.getDistrict())
                .divisionalSecretariat(addressDto.getDivisionalSecretariat())
                .gramaNiladhariDivision(addressDto.getGramaNiladhariDivision())
                .build();

        return CitizenUser.builder()
                .id(UUID.randomUUID())
                .fullName(request.getPersonalInfo().getFullName())
                .nic(request.getPersonalInfo().getNic())
                .email(request.getContactInfo().getEmail())
                .phone(request.getContactInfo().getPhone())
                .dateOfBirth(request.getPersonalInfo().getDateOfBirth())
                .gender(request.getPersonalInfo().getGender())
                .nationality("Sri Lankan")
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

    private CitizenRegistrationDto createCitizenRegistration(CitizenUser user, UserRegistrationRequestDto request, BiometricIPFSHashes hashes) {
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

    private CitizenUser findUserByIdentifier(String identifier) {
        return citizenUserRepository.findByEmailOrNicOrDidId(identifier, identifier, identifier);
    }

    private BiometricData retrieveStoredBiometricData(CitizenUser user) {
        try {
            byte[] fingerprintData = ipfsService.retrieveFile(user.getFingerprintIpfsHash());
            byte[] faceData = ipfsService.retrieveFile(user.getFaceImageIpfsHash());

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
                String hash = ipfsService.storeFile(path, doc.getBytes());
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
