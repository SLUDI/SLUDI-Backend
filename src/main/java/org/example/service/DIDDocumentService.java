package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.entity.*;
import org.example.enums.ProofPurpose;
import org.example.enums.UserStatus;
import org.example.exception.ErrorCodes;
import org.example.repository.*;
import org.example.integration.IPFSIntegration;
import org.example.integration.AIIntegration;
import org.example.security.CryptographyService;
import org.example.exception.SludiException;
import org.example.utils.DIDIdGenerator;
import org.example.utils.HashUtil;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.security.MessageDigest;
import java.util.concurrent.CompletableFuture;

@Slf4j
@Service
@Transactional
public class DIDDocumentService {

    private final IPFSIntegration ipfsIntegration;
    private final HyperledgerService hyperledgerService;
    private final DigitalSignatureService digitalSignatureService;
    private final AIIntegration aiIntegration;
    private final CryptographyService cryptographyService;
    private final OrganizationUserService organizationUserService;
    private final OrganizationUserRepository organizationUserRepository;
    private final CitizenUserRepository citizenUserRepository;
    private final DIDDocumentRepository didDocumentRepository;
    private final AuthenticationLogRepository authLogRepository;
    private final IPFSContentRepository ipfsContentRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public DIDDocumentService(
            IPFSIntegration ipfsIntegration,
            HyperledgerService hyperledgerService,
            DigitalSignatureService digitalSignatureService,
            AIIntegration aiIntegration,
            CryptographyService cryptographyService,
            OrganizationUserService organizationUserService,
            OrganizationUserRepository organizationUserRepository,
            CitizenUserRepository citizenUserRepository,
            DIDDocumentRepository didDocumentRepository,
            AuthenticationLogRepository authLogRepository,
            IPFSContentRepository ipfsContentRepository
    ) {
        this.ipfsIntegration = ipfsIntegration;
        this.hyperledgerService = hyperledgerService;
        this.digitalSignatureService = digitalSignatureService;
        this.aiIntegration = aiIntegration;
        this.cryptographyService = cryptographyService;
        this.organizationUserService = organizationUserService;
        this.organizationUserRepository = organizationUserRepository;
        this.citizenUserRepository = citizenUserRepository;
        this.didDocumentRepository = didDocumentRepository;
        this.authLogRepository = authLogRepository;
        this.ipfsContentRepository = ipfsContentRepository;
    }

    /**
     * Create DID Document
     */
    public DIDCreateResponseDto createDID(DIDCreateRequestDto request, String userName) {
        try {
            // Find user
            OrganizationUser adminUser = organizationUserRepository.findByUsername(userName)
                    .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

            // Check if user has permission to issue DID
            if (!organizationUserService.verifyUserPermission(userName, "citizen:issue_did")) {
                log.warn("User {} attempted to issue DID without permission", userName);
                throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
            }

            // Verify user is active
            if (adminUser.getStatus() != UserStatus.ACTIVE) {
                log.warn("Inactive user {} attempted to issue DID", userName);
                throw new SludiException(ErrorCodes.USER_INACTIVE);
            }

            // Validate input data
            validateDIDCreateRequest(request);

            // Check if user exists
            CitizenUser citizenUser = citizenUserRepository.findByAnyHash(null, HashUtil.sha256(request.getNic()), null);

            if (citizenUser == null) {
                log.info("User doesn't exists with NIC: {}", request.getNic());
                throw new SludiException(ErrorCodes.USER_NOT_FOUND, request.getNic());
            }

            if (citizenUser.getDidId() != null) {
                log.error("This user already has DID");
                throw new SludiException(ErrorCodes.USER_ALREADY_HAS_DID, citizenUser.getDidId());
            }

            // Convert user entity to JSON string
            CitizenUserDto dto = CitizenUserDto.builder()
                    .id(citizenUser.getId())
                    .citizenCode(citizenUser.getCitizenCode())
                    .fullName(citizenUser.getFullName())
                    .nic(citizenUser.getNic())
                    .age(citizenUser.getAge())
                    .email(citizenUser.getEmail())
                    .phone(citizenUser.getPhone())
                    .dateOfBirth(citizenUser.getDateOfBirth().toString())
                    .gender(citizenUser.getGender())
                    .nationality(citizenUser.getNationality())
                    .citizenship(citizenUser.getCitizenship())
                    .bloodGroup(citizenUser.getBloodGroup())
                    .address(citizenUser.getAddress())
                    .supportingDocuments(citizenUser.getSupportingDocuments())
                    .status(citizenUser.getStatus())
                    .verificationStatus(citizenUser.getVerificationStatus())
                    .didId(citizenUser.getDidId())
                    .publicKey(citizenUser.getPublicKey())
                    .fingerprintIpfsHash(citizenUser.getFingerprintIpfsHash())
                    .faceImageIpfsHash(citizenUser.getFaceImageIpfsHash())
                    .signatureIpfsHash(citizenUser.getSignatureIpfsHash())
                    .profilePhotoIpfsHash(citizenUser.getProfilePhotoIpfsHash())
                    .createdAt(citizenUser.getCreatedAt())
                    .updatedAt(citizenUser.getUpdatedAt())
                    .lastLogin(citizenUser.getLastLogin())
                    .build();
            String userData = objectMapper.writeValueAsString(dto);

            // Create DID ID
            LocalDate dob = citizenUser.getDateOfBirth();
            DIDIdGenerator.Gender gender =
                    citizenUser.getGender().equalsIgnoreCase("FEMALE")
                            ? DIDIdGenerator.Gender.FEMALE
                            : DIDIdGenerator.Gender.MALE;

            String didId = DIDIdGenerator.generateDID(dob, gender);

            String timeNow = LocalDateTime.now().toString();

            // Create Proof of Data
            ProofData proofData = digitalSignatureService.signDIDDocument(
                    userData,
                    didId,
                    adminUser
            );

            // Create DID on Hyperledger Fabric
            DIDDocumentDto didResult = hyperledgerService.createDID(didId, timeNow, proofData);

            // Save DID Document
            DIDDocument didDocument = DIDDocument.builder()
                    .id(didResult.getId())
                    .didVersion(didResult.getDidVersion())
                    .didCreated(didResult.getDidCreated())
                    .didUpdated(didResult.getDidUpdated())
                    .services(new ArrayList<>())
                    .publicKey(new ArrayList<>())
                    .authentication(didResult.getAuthentication())
                    .status(didResult.getStatus())
                    .proof(proofData)
                    .blockchainTxId(didResult.getBlockchainTxId())
                    .blockNumber(didResult.getBlockNumber())
                    .build();

            // Map services
            List<Services> servicesList = new ArrayList<>();
            if(didResult.getServices() != null) {
                for (ServiceDto serviceDto : didResult.getServices()) {
                    Services service = Services.builder()
                            .id(serviceDto.getId())
                            .type(serviceDto.getType())
                            .serviceEndpoint(serviceDto.getServiceEndpoint())
                            .didDocument(didDocument)
                            .build();
                    servicesList.add(service);
                }
            }

            // Map public keys
            List<PublicKey> publicKeyList = new ArrayList<>();
            if(didResult.getPublicKeys() != null) {
                for (PublicKeyDto publicKeyDto : didResult.getPublicKeys()) {
                    PublicKey publicKey = PublicKey.builder()
                            .id(publicKeyDto.getId())
                            .type(publicKeyDto.getType())
                            .controller(publicKeyDto.getController())
                            .publicKeyStr(publicKeyDto.getPublicKeyStr())
                            .didDocument(didDocument)
                            .build();
                    publicKeyList.add(publicKey);
                }
            }

            didDocument.setServices(servicesList);
            didDocument.setPublicKey(publicKeyList);

            didDocumentRepository.save(didDocument);

            citizenUser.setDidId(didResult.getId());
            citizenUser.setStatus(UserStatus.ACTIVE);
            citizenUser.setUpdatedAt(LocalDateTime.now().toString());

            citizenUser = citizenUserRepository.save(citizenUser);

            // Log the registration activity
            logUserActivity(citizenUser.getId().toString(), "DID_CREATION", "User DID creation successfully", request.getDeviceInfo());

            // Return success response
            return DIDCreateResponseDto.builder()
                    .userId(citizenUser.getId())
                    .didId(citizenUser.getDidId())
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
        return citizenUserRepository.existsByNicHash(HashUtil.sha256(nic));
    }

    public boolean isCitizenUserExistsByEmail(String email) {
        return citizenUserRepository.existsByEmailHash(HashUtil.sha256(email));
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

        CitizenUser user = citizenUserRepository.findByAnyHash(null, null, HashUtil.sha256(didId));
        if(user==null) {
            throw new SludiException(ErrorCodes.USER_NOT_FOUND);
        }
    }

    /**
     * Deactivate user account
     */
    public String deactivateDID(UUID userId, String reason) {
        try {
            CitizenUser user = citizenUserRepository.findById(userId)
                    .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

            // Deactivate DID on blockchain
            hyperledgerService.deactivateDID(user.getDidId());

            // Update user status
            user.setStatus(UserStatus.DEACTIVATED);
            user.setUpdatedAt(LocalDateTime.now().toString());
            citizenUserRepository.save(user);

            // Log deactivation
            logUserActivity(userId.toString(), "USER_DEACTIVATION", "User deactivated: " + reason, null);

            return "User account deactivated successfully";

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.USER_DEACTIVATION_FAILED, e.getMessage(), e);
        }
    }

    /**
     * Delete DID document
     */
    public String deleteDID(String did) {
        try {
            DIDDocument user = didDocumentRepository.findById(did)
                    .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

            // Delete DID on blockchain
            hyperledgerService.deleteDID(did);

            // Delete DID on PostgreSQL
            didDocumentRepository.deleteById(did);

            // Log deactivation
            logUserActivity(did, "DID_DELETE", "Delete DID Document: ", null);

            return "DID Document delete successfully";

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.DID_DELETION_FAILED, e.getMessage(), e);
        }
    }

    public Map<String, Object> getUserStatistics() {
        try {
            long totalUsers = citizenUserRepository.count();
            long activeUsers = citizenUserRepository.countByStatus(UserStatus.ACTIVE);
            long inactiveUsers = citizenUserRepository.countByStatus(UserStatus.INACTIVE);
            long deactivatedUsers = citizenUserRepository.countByStatus(UserStatus.DEACTIVATED);

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

    private void validateDIDCreateRequest(DIDCreateRequestDto request) {
        if (request.getNic() == null) {
            throw new SludiException(ErrorCodes.INVALID_INPUT, "NIC is required");
        }

        String nic = request.getNic();
        if (!nic.matches("\\d{12}") && !nic.matches("\\d{9}[VX]")) {
            throw new SludiException(ErrorCodes.INVALID_NIC, "Invalid NIC format");
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
            return citizenUserRepository.findByAnyHash(HashUtil.sha256(identifier), null, null);
        } else if(type=="NIC") {
            return citizenUserRepository.findByAnyHash(null, HashUtil.sha256(identifier), null);
        } else if(type=="DID") {
            return citizenUserRepository.findByAnyHash(null, null, HashUtil.sha256(identifier));
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

    private void logUserActivity(String userId, String activityType, String description, DeviceInfoDto deviceInfo) {
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

    private void logSuccessfulAuthentication(String userId, String userDid, String authMethod, DeviceInfoDto deviceInfo) {
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
}