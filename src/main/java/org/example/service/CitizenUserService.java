package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.dto.*;
import org.example.entity.*;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.integration.IPFSIntegration;
import org.example.repository.AuthenticationLogRepository;
import org.example.repository.CitizenUserRepository;
import org.example.repository.IPFSContentRepository;
import org.example.utils.CitizenCodeGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
@Transactional
public class CitizenUserService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CitizenUserService.class);

    @Autowired
    private CitizenUserRepository citizenUserRepository;

    @Autowired
    private AuthenticationLogRepository authLogRepository;

    @Autowired
    private IPFSContentRepository ipfsContentRepository;

    @Autowired
    private IPFSIntegration ipfsIntegration;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Register a new user with complete identity setup
     */
    public CitizenUserRegistrationResponseDto registerCitizenUser(CitizenUserRegistrationRequestDto request) {
        LOGGER.info("Starting citizen user registration process for NIC: {}, Email: {}",
                request.getPersonalInfo().getNic(), request.getContactInfo().getEmail());

        try {
            // Validate input data
            validateRegistrationRequest(request);
            LOGGER.debug("Registration request validation passed for NIC: {}", request.getPersonalInfo().getNic());

            // Check for duplicates
            if (citizenUserRepository.existsByNic(request.getPersonalInfo().getNic())) {
                LOGGER.warn("User already exists with NIC: {}", request.getPersonalInfo().getNic());
                throw new SludiException(ErrorCodes.USER_EXISTS_WITH_NIC, request.getPersonalInfo().getNic());
            }

            if (citizenUserRepository.existsByEmail(request.getContactInfo().getEmail())) {
                LOGGER.warn("User already exists with Email: {}", request.getContactInfo().getEmail());
                throw new SludiException(ErrorCodes.USER_EXISTS_WITH_EMAIL, request.getContactInfo().getEmail());
            }

            // Generate citizen code
            String citizenCode = CitizenCodeGenerator.generateCitizenCode();
            LOGGER.debug("Generated citizen code: {}", citizenCode);

            // Create entity
            CitizenUser user = createUserEntity(request);
            user.setCitizenCode(citizenCode);
            user.setCreatedAt(LocalDateTime.now().toString());
            user.setUpdatedAt(LocalDateTime.now().toString());

            // Handle document uploads
            if (request.getSupportingDocuments() != null && !request.getSupportingDocuments().isEmpty()) {
                LOGGER.info("Uploading {} supporting documents for NIC: {}",
                        request.getSupportingDocuments().size(), request.getPersonalInfo().getNic());

                List<SupportingDocumentResponseDto> documentHashes =
                        storeUserDocuments(user.getId(), request.getSupportingDocuments());

                List<SupportingDocument> supportingDocuments = documentHashes.stream()
                        .map(doc -> SupportingDocument.builder()
                                .name(doc.getName())
                                .ipfsCid(doc.getIpfsCid())
                                .fileType(doc.getFileType())
                                .side(doc.getSide())
                                .build())
                        .collect(Collectors.toList());

                user.setSupportingDocuments(supportingDocuments);
            }

            // Save entity
            user = citizenUserRepository.save(user);
            LOGGER.info("Citizen user registered successfully with ID: {}, Code: {}", user.getId(), user.getCitizenCode());

            // Log activity
            logUserActivity(user.getId(), "USER_REGISTRATION", "User registered successfully", request.getDeviceInfo());

            // Build response
            return CitizenUserRegistrationResponseDto.builder()
                    .userId(user.getId())
                    .citizenCode(user.getCitizenCode())
                    .status(user.getStatus().toString())
                    .message("User registered successfully")
                    .build();

        } catch (SludiException ex) {
            LOGGER.error("Registration failed due to known error: {}", ex.getMessage(), ex);
            throw ex;
        } catch (Exception ex) {
            LOGGER.error("Unexpected error during registration for NIC: {}", request.getPersonalInfo().getNic(), ex);
            throw new SludiException(ErrorCodes.USER_REGISTRATION_FAILED, ex);
        }
    }


    /**
     * Uploads a profile photo to IPFS and links it to a CitizenUser by DID.
     *
     * @param did User DID
     * @param profilePhoto Profile photo as MultipartFile
     */
    public void citizenUserProfilePhotoUpload(String did, MultipartFile profilePhoto) {

        CitizenUser citizenUser = Optional.ofNullable(
                        citizenUserRepository.findByEmailOrNicOrDidId(null, null, did))
                .orElseThrow(() -> {
                    LOGGER.warn("No user found with DID: {}", did);
                    return new IllegalArgumentException("CitizenUser not found for DID: " + did);
                });

        storeProfilePhotoAsync(citizenUser.getId(), profilePhoto)
                .thenAccept(hash -> {
                    citizenUser.setProfilePhotoIpfsHash(hash);
                    citizenUserRepository.save(citizenUser);
                    LOGGER.info("Successfully uploaded profile photo for user {}. IPFS hash: {}",
                            citizenUser.getId(), hash);
                })
                .exceptionally(ex -> {
                    LOGGER.error("Async error while uploading profile photo for DID {}: {}", did, ex.getMessage(), ex);
                    return null;
                });
    }

    /**
     * Retrieve user profile information
     */
    public CitizenUserProfileResponseDto getUserProfile(String did) {
        try {
            CitizenUser user = citizenUserRepository.findByEmailOrNicOrDidId(null, null, did);

            if(user == null) {
                throw new SludiException(ErrorCodes.USER_NOT_FOUND);
            }

            // Log access attempt
            logUserActivity(user.getId(), "PROFILE_ACCESS", "Profile accessed by: " + did, null);

            return createUserProfileResponse(user);

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.FAILD_TO_RETRIEVE_USER_PROFILE, e.getMessage(), e);
        }
    }

    /**
     * Update user profile information
     */
    public CitizenUserProfileResponseDto updateUserProfile(String did, CitizenUserProfileUpdateRequestDto request) {
        try {
            CitizenUser user = citizenUserRepository.findByEmailOrNicOrDidId(null, null, did);

            if(user == null) {
                throw new SludiException(ErrorCodes.USER_NOT_FOUND);
            }

            // Validate update permissions
            if (!CitizenUser.UserStatus.ACTIVE.equals(user.getStatus())) {
                throw new SludiException(ErrorCodes.CANNOT_UPDATE_INACTIVE_USER);
            }

            // Store old values for audit
            Map<String, Object> oldValues = createAuditMap(user);

            // Update profile information
            updateUserFields(user, request);

            user.setUpdatedAt(LocalDateTime.now().toString());
            user = citizenUserRepository.save(user);

            // Create audit log
            logUserActivity(user.getId(), "PROFILE_UPDATE", "Profile updated successfully", request.getDeviceInfo());
            createAuditTrail(user.getId(), "update", "user", user.getId().toString(), oldValues, createAuditMap(user), "Profile update");

            return createUserProfileResponse(user);

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.USER_PROFILE_UPDATE_FAILED, e.getMessage(), e);
        }
    }

    private void validateRegistrationRequest(CitizenUserRegistrationRequestDto request) {
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

    private CitizenUser createUserEntity(CitizenUserRegistrationRequestDto request) {
        AddressDto addressDto = request.getPersonalInfo().getAddress();
        Address address = Address.builder()
                .street(addressDto.getStreet())
                .city(addressDto.getCity())
                .district(addressDto.getDistrict())
                .postalCode(addressDto.getPostalCode())
                .divisionalSecretariat(addressDto.getDivisionalSecretariat())
                .gramaNiladhariDivision(addressDto.getGramaNiladhariDivision())
                .province(addressDto.getProvince())
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
                .bloodGroup(request.getPersonalInfo().getBloodGroup())
                .address(address)
                .status(CitizenUser.UserStatus.PENDING)
                .kycStatus(CitizenUser.KYCStatus.NOT_STARTED)
                .createdAt(LocalDateTime.now().toString())
                .updatedAt(LocalDateTime.now().toString())
                .build();
    }

    /**
     * Stores profile photo in IPFS asynchronously.
     *
     * @param userId       CitizenUser ID
     * @param profilePhoto Profile photo file
     * @return CompletableFuture with IPFS hash
     */
    private CompletableFuture<String> storeProfilePhotoAsync(UUID userId, MultipartFile profilePhoto) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                LOGGER.debug("Storing profile photo in IPFS for user {}", userId);

                String path = String.format("profile/users/%s/profile_photo.jpg", userId);
                String hash = ipfsIntegration.storeFile(path, profilePhoto.getBytes());

                LOGGER.debug("Profile photo stored in IPFS for user {}. Hash: {}", userId, hash);

                recordIPFSContent(userId, hash, "profile", "photo", "image/jpeg");
                return hash;
            } catch (Exception e) {
                LOGGER.error("Failed to store profile photo in IPFS for user {}: {}", userId, e.getMessage(), e);
                throw new RuntimeException("Failed to store profile photo in IPFS", e);
            }
        });
    }

    private List<SupportingDocumentResponseDto> storeUserDocuments(UUID userId, List<SupportingDocumentRequestDto> documents) {
        List<SupportingDocumentResponseDto> supportingDocumentResponseDtos = new ArrayList<>();
        for (SupportingDocumentRequestDto doc : documents) {
            try {
                String path = String.format("documents/users/%s/%s", userId, doc.getName());
                String hash = ipfsIntegration.storeFile(path, doc.getFile().getBytes());

                SupportingDocumentResponseDto supportingDocumentResponseDto = SupportingDocumentResponseDto.builder()
                        .name(doc.getName())
                        .ipfsCid(hash)
                        .fileType(doc.getType())
                        .side(doc.getSide())
                        .build();
                supportingDocumentResponseDtos.add(supportingDocumentResponseDto);
                recordIPFSContent(userId, hash, "document", "user_document", doc.getType());
            } catch (Exception e) {
                throw new RuntimeException("Failed to store document: " + doc.getFile(), e);
            }
        }
        return supportingDocumentResponseDtos;
    }

    /**
     * Records metadata about uploaded IPFS content in DB.
     */
    private void recordIPFSContent(UUID userId, String ipfsHash, String category, String subcategory, String mimeType) {
        LOGGER.debug("Recording IPFS content for user {} with hash {}", userId, ipfsHash);

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

        LOGGER.info("IPFS content recorded for user {}. Hash: {}", userId, ipfsHash);
    }

    private CitizenUserProfileResponseDto createUserProfileResponse(CitizenUser user) {

        return CitizenUserProfileResponseDto.builder()
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
                        .province("")
                        .postalCode("")
                        .district("")
                        .divisionalSecretariat("")
                        .gramaNiladhariDivision("")
                        .build();
            }

            return AddressDto.builder()
                    .street(address.getStreet())
                    .city(address.getCity())
                    .province(address.getProvince())
                    .postalCode(address.getPostalCode())
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

    private void updateUserFields(CitizenUser user, CitizenUserProfileUpdateRequestDto request) {
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
                    .province(request.getAddress().getProvince())
                    .postalCode(request.getAddress().getPostalCode())
                    .district(request.getAddress().getDistrict())
                    .divisionalSecretariat(request.getAddress().getDivisionalSecretariat())
                    .gramaNiladhariDivision(request.getAddress().getGramaNiladhariDivision())
                    .build();
            user.setAddress(newAddress);
        }
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
                    .province(currentAddress.getProvince())
                    .postalCode(currentAddress.getPostalCode())
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

    private void logUserActivity(UUID userId, String activityType, String description, DeviceInfoDto deviceInfo) {
        AuthenticationLog log = AuthenticationLog.builder()
                .id(UUID.randomUUID())
                .userId(userId)
                .authType(activityType)
                .result(description)
                .deviceInfo(deviceInfo != null ? convertDeviceInfoToJson(deviceInfo) : null)
                .attemptedAt(LocalDateTime.now())
                .completedAt(LocalDateTime.now())
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

    private Map<String, Object> createAuditMap(CitizenUser user) {
        Map<String, Object> map = new HashMap<>();
        map.put("fullName", user.getFullName());
        map.put("email", user.getEmail());
        map.put("phone", user.getPhone());
        map.put("status", user.getStatus().toString());
        map.put("updatedAt", user.getUpdatedAt());
        return map;
    }

    private void createAuditTrail(UUID userId, String actionType, String resourceType, String resourceId,
                                  Map<String, Object> oldValues, Map<String, Object> newValues, String reason) {
        // Implementation would create audit trail record
        // This is a placeholder for the audit functionality
    }
}
