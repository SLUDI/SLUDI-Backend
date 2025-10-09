package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
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

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.security.MessageDigest;
import java.util.concurrent.CompletableFuture;

@Slf4j
@Service
@Transactional
public class DIDDocumentService {

    @Autowired
    private CitizenUserRepository citizenUserRepository;

    @Autowired
    private DIDDocumentRepository didDocumentRepository;

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
     * Create DID Document
     */
    public DIDCreateResponseDto createDID(DIDCreateRequestDto request) {
        try {
            // Validate input data
            validateDIDCreateRequest(request);

            // Check if user exists
            CitizenUser citizenUser = citizenUserRepository.findByEmailOrNicOrDidId(null, request.getNic(), null);

            if (citizenUser == null) {
                log.info("User doesn't exists with NIC: {}", request.getNic());
                throw new SludiException(ErrorCodes.USER_NOT_FOUND, request.getNic());
            }

            if (citizenUser.getDidId() != null) {
                log.error("This user already has DID");
                throw new SludiException(ErrorCodes.USER_ALREADY_HAS_DID, citizenUser.getDidId());
            }

            // Convert user entity to JSON string
            CitizenUserDTO dto = CitizenUserDTO.builder()
                    .id(citizenUser.getId())
                    .citizenCode(citizenUser.getCitizenCode())
                    .fullName(citizenUser.getFullName())
                    .nic(citizenUser.getNic())
                    .age(citizenUser.getAge())
                    .email(citizenUser.getEmail())
                    .phone(citizenUser.getPhone())
                    .dateOfBirth(citizenUser.getDateOfBirth())
                    .gender(citizenUser.getGender())
                    .nationality(citizenUser.getNationality())
                    .citizenship(citizenUser.getCitizenship())
                    .bloodGroup(citizenUser.getBloodGroup())
                    .address(citizenUser.getAddress())
                    .supportingDocuments(citizenUser.getSupportingDocuments())
                    .status(citizenUser.getStatus())
                    .kycStatus(citizenUser.getKycStatus())
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
            LocalDate dob = LocalDate.parse(citizenUser.getDateOfBirth());
            DIDIdGenerator.Gender gender =
                    citizenUser.getGender().equalsIgnoreCase("FEMALE")
                            ? DIDIdGenerator.Gender.FEMALE
                            : DIDIdGenerator.Gender.MALE;

            String didId = DIDIdGenerator.generateDID(dob, gender);

            String timeNow = LocalDateTime.now().toString();

            // Create Proof of Data
            ProofData proofData = digitalSignatureService.createProofData(
                    userData,
                    didId,
                    timeNow,
                    ProofPurpose.DID_CREATION.getValue()
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
            citizenUser.setStatus(CitizenUser.UserStatus.ACTIVE);
            citizenUser.setUpdatedAt(LocalDateTime.now().toString());

            citizenUser = citizenUserRepository.save(citizenUser);

            // Log the registration activity
            logUserActivity(citizenUser.getId(), "DID_CREATION", "User DID creation successfully", request.getDeviceInfo());

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
