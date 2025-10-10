package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
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

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional
public class CitizenUserService {

    @Autowired
    private CitizenUserRepository citizenUserRepository;

    @Autowired
    private AuthenticationLogRepository authLogRepository;

    @Autowired
    private IPFSContentRepository ipfsContentRepository;

    @Autowired
    private IPFSIntegration ipfsIntegration;

    @Autowired
    private AppointmentService appointmentService;

    @Autowired
    private CitizenCodeGenerator citizenCodeGenerator;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Register a new user with complete identity setup
     */
    public CitizenUserRegistrationResponseDto registerCitizenUser(CitizenUserRegistrationRequestDto request) {
        log.info("Starting citizen user registration process for NIC: {}, Email: {}",
                request.getPersonalInfo().getNic(), request.getContactInfo().getEmail());

        try {
            // Validate input data
            validateRegistrationRequest(request);
            log.debug("Registration request validation passed for NIC: {}", request.getPersonalInfo().getNic());

            // Check for duplicates
            if (citizenUserRepository.existsByNic(request.getPersonalInfo().getNic())) {
                log.warn("User already exists with NIC: {}", request.getPersonalInfo().getNic());
                throw new SludiException(ErrorCodes.USER_EXISTS_WITH_NIC, request.getPersonalInfo().getNic());
            }

            if (citizenUserRepository.existsByEmail(request.getContactInfo().getEmail())) {
                log.warn("User already exists with Email: {}", request.getContactInfo().getEmail());
                throw new SludiException(ErrorCodes.USER_EXISTS_WITH_EMAIL, request.getContactInfo().getEmail());
            }

            // Generate citizen code
            String citizenCode = citizenCodeGenerator.generateCitizenCode();
            log.debug("Generated citizen code: {}", citizenCode);

            // Create entity
            CitizenUser user = createUserEntity(request);
            user.setCitizenCode(citizenCode);
            user.setCreatedAt(LocalDateTime.now().toString());
            user.setUpdatedAt(LocalDateTime.now().toString());

            // Handle document uploads
            if (request.getSupportingDocuments() != null && !request.getSupportingDocuments().isEmpty()) {
                log.info("Uploading {} supporting documents for NIC: {}",
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
            log.info("Citizen user registered successfully with ID: {}, Code: {}", user.getId(), user.getCitizenCode());

            // Save user preferred date
            LocalDate selectedDate = request.getSelectedDate();
            String district = request.getPersonalInfo().getAddress().getDistrict();

            appointmentService.savePreferredDate(user.getId(), selectedDate, district);

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
            log.error("Registration failed due to known error: {}", ex.getMessage(), ex);
            throw ex;
        } catch (Exception ex) {
            log.error("Unexpected error during registration for NIC: {}", request.getPersonalInfo().getNic(), ex);
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
                    log.warn("No user found with DID: {}", did);
                    return new IllegalArgumentException("CitizenUser not found for DID: " + did);
                });

        storeProfilePhotoAsync(citizenUser.getId(), profilePhoto)
                .thenAccept(hash -> {
                    citizenUser.setProfilePhotoIpfsHash(hash);
                    citizenUserRepository.save(citizenUser);
                    log.info("Successfully uploaded profile photo for user {}. IPFS hash: {}",
                            citizenUser.getId(), hash);
                })
                .exceptionally(ex -> {
                    log.error("Async error while uploading profile photo for DID {}: {}", did, ex.getMessage(), ex);
                    return null;
                });
    }

    /**
     * Retrieve user profile information
     */
    public GetCitizenUserProfileResponseDto getUserProfile(GetCitizenUserProfileRequestDto request) {
        try {
            CitizenUser user = citizenUserRepository.findById(request.getId())
                    .orElseThrow(() -> new SludiException(
                            ErrorCodes.USER_NOT_FOUND,
                            "User not found with ID: " + request.getId()
                    ));

            DeviceInfoDto deviceInfoDto = DeviceInfoDto.builder()
                    .deviceId(request.getDeviceId())
                    .os(request.getOs())
                    .deviceType(request.getDeviceType())
                    .ipAddress(request.getIpAddress())
                    .location(request.getLocation())
                    .build();

            // Log access attempt
            logUserActivity(user.getId(), "PROFILE_ACCESS", "Profile accessed by user", deviceInfoDto);

            return createUserProfileResponse(user);

        } catch (SludiException e) {
            throw e;
        } catch (Exception e) {
            throw new SludiException(
                    ErrorCodes.FAILD_TO_RETRIEVE_USER_PROFILE,
                    "Failed to retrieve user profile for ID: " + request.getId(),
                    e
            );
        }
    }

    public List<GetCitizenUserProfileResponseDto> getAllUserProfiles() {
        log.info("Fetching all citizen user profiles");

        try {
            List<CitizenUser> users = citizenUserRepository.findAll();

            if (users.isEmpty()) {
                log.warn("No citizen users found in the system");
                return Collections.emptyList();
            }

            List<GetCitizenUserProfileResponseDto> responseList = users.stream()
                    .map(this::createUserProfileResponse)
                    .collect(Collectors.toList());

            log.info("Successfully retrieved {} citizen user profiles", responseList.size());

            return responseList;

        } catch (Exception e) {
            log.error("Unexpected error while fetching all citizen user profiles", e);
            throw new SludiException(
                    ErrorCodes.FAILD_TO_RETRIEVE_USER_PROFILE,
                    "Failed to retrieve all citizen user profiles",
                    e
            );
        }
    }

    /**
     * Retrieve user document information
     */
    public List<GetSupportingDocumentResponseDto> getSupportingDocument(UUID id) {
        log.info("Fetching supporting documents for CitizenUser ID: {}", id);

        try {
            CitizenUser user = citizenUserRepository.findById(id)
                    .orElseThrow(() -> {
                        log.warn("CitizenUser not found for ID: {}", id);
                        return new SludiException(
                                ErrorCodes.USER_NOT_FOUND,
                                "User not found with ID: " + id
                        );
                    });

            List<SupportingDocument> supportingDocuments = user.getSupportingDocuments();

            if (supportingDocuments == null || supportingDocuments.isEmpty()) {
                log.info("No supporting documents found for CitizenUser ID: {}", id);
                return Collections.emptyList();
            }

            List<GetSupportingDocumentResponseDto> responseList = retrievesUserDocument(supportingDocuments);

            log.info("Successfully retrieved {} supporting document(s) for CitizenUser ID: {}",
                    responseList.size(), id);

            return responseList;

        } catch (SludiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error while fetching supporting documents for CitizenUser ID: {}", id, e);
            throw new SludiException(ErrorCodes.IPFS_RETRIEVAL_FAILED,
                    "Error retrieving supporting documents for user " + id, e);
        }
    }


    /**
     * Update user profile information
     */
    public GetCitizenUserProfileResponseDto updateUserProfile(String did, CitizenUserProfileUpdateRequestDto request) {
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
                log.debug("Storing profile photo in IPFS for user {}", userId);

                String path = String.format("profile/users/%s/profile_photo.jpg", userId);
                String hash = ipfsIntegration.storeFile(path, profilePhoto.getBytes());

                log.debug("Profile photo stored in IPFS for user {}. Hash: {}", userId, hash);

                recordIPFSContent(userId, hash, "profile", "photo", "image/jpeg");
                return hash;
            } catch (Exception e) {
                log.error("Failed to store profile photo in IPFS for user {}: {}", userId, e.getMessage(), e);
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

    private List<GetSupportingDocumentResponseDto> retrievesUserDocument(List<SupportingDocument> supportingDocumentsList) {
        List<GetSupportingDocumentResponseDto> responseList = new ArrayList<>();

        for (SupportingDocument doc : supportingDocumentsList) {
            try {
                log.debug("Retrieving file from IPFS for CID: {}", doc.getIpfsCid());

                byte[] fileContent = ipfsIntegration.retrieveFile(doc.getIpfsCid());

                GetSupportingDocumentResponseDto responseDto = GetSupportingDocumentResponseDto.builder()
                        .name(doc.getName())
                        .file(Base64.getEncoder().encodeToString(fileContent))
                        .fileType(doc.getFileType())
                        .side(doc.getSide())
                        .build();

                responseList.add(responseDto);

            } catch (Exception ex) {
                log.error("Failed to retrieve file from IPFS for CID: {} (Document: {})",
                        doc.getIpfsCid(), doc.getName(), ex);

                throw new SludiException(ErrorCodes.IPFS_RETRIEVAL_FAILED,
                        "Failed to retrieve supporting document: " + doc.getName(), ex);
            }
        }
        return responseList;
    }

    /**
     * Records metadata about uploaded IPFS content in DB.
     */
    private void recordIPFSContent(UUID userId, String ipfsHash, String category, String subcategory, String mimeType) {
        log.debug("Recording IPFS content for user {} with hash {}", userId, ipfsHash);

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

        log.info("IPFS content recorded for user {}. Hash: {}", userId, ipfsHash);
    }

    private GetCitizenUserProfileResponseDto createUserProfileResponse(CitizenUser user) {
        try {
            // Retrieve supporting documents
            List<GetSupportingDocumentResponseDto> responseList = retrievesUserDocument(user.getSupportingDocuments())
                    .stream()
                    .map(doc -> GetSupportingDocumentResponseDto.builder()
                            .name(doc.getName())
                            .file(doc.getFile())
                            .fileType(doc.getFileType())
                            .side(doc.getSide())
                            .build())
                    .collect(Collectors.toList());

            return GetCitizenUserProfileResponseDto.builder()
                    .userId(user.getId())
                    .citizenCode(user.getCitizenCode())
                    .fullName(user.getFullName())
                    .nic(user.getNic())
                    .age(user.getAge()) // added age
                    .email(user.getEmail())
                    .phone(user.getPhone())
                    .dateOfBirth(user.getDateOfBirth())
                    .gender(user.getGender())
                    .nationality(user.getNationality())
                    .address(user.getAddress() != null ? convertJsonToAddress(user.getAddress()) : null)
                    .status(user.getStatus() != null ? user.getStatus().toString() : null)
                    .kycStatus(user.getKycStatus() != null ? user.getKycStatus().toString() : null)
                    .supportingDocumentList(responseList)
                    .createdAt(user.getCreatedAt())
                    .updatedAt(user.getUpdatedAt())
                    .lastLogin(user.getLastLogin())
                    .build();
        } catch (Exception e) {
            log.error("Failed to create user profile response for ID: {}", user.getId(), e);
            throw new SludiException(
                    ErrorCodes.FAILD_TO_RETRIEVE_USER_PROFILE,
                    "Failed to build user profile response for ID: " + user.getId(),
                    e
            );
        }
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
