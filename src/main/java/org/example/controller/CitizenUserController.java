package org.example.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.exception.ErrorCodes;
import org.example.exception.HttpStatusHandler;
import org.example.exception.SludiException;
import org.example.service.CitizenUserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/citizen-user")
@CrossOrigin(origins = "*")
public class CitizenUserController {
    
    private final CitizenUserService citizenUserService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public CitizenUserController(CitizenUserService citizenUserService) {
        this.citizenUserService = citizenUserService;
    }

    /**
     * Register new user and create DID
     * POST /api/citizen-user/register
     */
    @PostMapping(value = "/register", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponseDto<CitizenUserRegistrationResponseDto>> registerUser(
            @Valid @RequestParam("fullName") String fullName,
            @Valid @RequestParam("nic") String nic,
            @Valid @RequestParam("age") String age,
            @Valid @RequestParam("dateOfBirth") LocalDate dateOfBirth,
            @Valid @RequestParam("citizenship") String citizenship,
            @Valid @RequestParam("gender") String gender,
            @Valid @RequestParam("nationality") String nationality,
            @Valid @RequestParam("bloodGroup") String bloodGroup,
            @Valid @RequestParam("email") String email,
            @Valid @RequestParam("phone") String phone,
            @Valid @RequestParam("street") String street,
            @Valid @RequestParam("city") String city,
            @Valid @RequestParam("district") String district,
            @Valid @RequestParam("postalCode") String postalCode,
            @Valid @RequestParam("divisionalSecretariat") String divisionalSecretariat,
            @Valid @RequestParam("gramaNiladhariDivision") String gramaNiladhariDivision,
            @Valid @RequestParam("province") String province,
            @Valid @RequestParam("selectDate") LocalDate selectDate,
            @Valid @RequestParam("deviceId") String deviceId,
            @Valid @RequestParam("deviceType") String deviceType,
            @Valid @RequestParam("os") String os,
            @Valid @RequestParam("ipAddress") String ipAddress,
            @Valid @RequestParam("location") String location,
            @RequestParam(value = "supportingDocuments") List<MultipartFile> files,
            @RequestParam(value = "documentTypes") List<String> documentTypes,
            @RequestParam(value = "documentSides") List<String> documentSides) {

        try {
            log.info("Received user registration NIC {}", nic);

            AddressDto addressDto = AddressDto.builder()
                    .street(street)
                    .city(city)
                    .district(district)
                    .postalCode(postalCode)
                    .divisionalSecretariat(divisionalSecretariat)
                    .gramaNiladhariDivision(gramaNiladhariDivision)
                    .province(province)
                    .build();

            PersonalInfoDto personalInfoDto = PersonalInfoDto.builder()
                    .fullName(fullName)
                    .nic(nic)
                    .age(age)
                    .dateOfBirth(dateOfBirth)
                    .citizenship(citizenship)
                    .gender(gender)
                    .nationality(nationality)
                    .bloodGroup(bloodGroup)
                    .address(addressDto)
                    .build();

            ContactInfoDto contactInfoDto = ContactInfoDto.builder()
                    .email(email)
                    .phone(phone)
                    .build();

            DeviceInfoDto deviceInfoDto = DeviceInfoDto.builder()
                    .deviceId(deviceId)
                    .deviceType(deviceType)
                    .os(os)
                    .ipAddress(ipAddress)
                    .location(location)
                    .build();

            List<SupportingDocumentRequestDto> docs = new ArrayList<>();

            if (files != null && !files.isEmpty()) {
                for (int i = 0; i < files.size(); i++) {
                    MultipartFile file = files.get(i);

                    String docType = (documentTypes != null && documentTypes.size() > i)
                            ? documentTypes.get(i)
                            : "UNKNOWN";

                    String docSide = (documentSides != null && documentSides.size() > i)
                            ? documentSides.get(i)
                            : "UNKNOWN";

                    docs.add(SupportingDocumentRequestDto.builder()
                            .name(file.getOriginalFilename())
                            .type(docType)    // NIC, Birth Certificate
                            .side(docSide)    // FRONT, BACK
                            .file(file)
                            .build());
                }
            }

            CitizenUserRegistrationRequestDto request = CitizenUserRegistrationRequestDto.builder()
                    .personalInfo(personalInfoDto)
                    .contactInfo(contactInfoDto)
                    .selectedDate(selectDate)
                    .supportingDocuments(docs)
                    .deviceInfo(deviceInfoDto)
                    .build();

            CitizenUserRegistrationResponseDto response = citizenUserService.registerCitizenUser(request);

            ApiResponseDto<CitizenUserRegistrationResponseDto> apiResponse =
                    ApiResponseDto.<CitizenUserRegistrationResponseDto>builder()
                            .success(true)
                            .message("User registered successfully")
                            .data(response)
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);

        } catch (SludiException ex) {
            log.error("User registration failed {}", ex.getMessage(), ex);

            ApiResponseDto<CitizenUserRegistrationResponseDto> apiResponse =
                    ApiResponseDto.<CitizenUserRegistrationResponseDto>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);

        } catch (Exception ex) {
            log.error("Unexpected error during registration {}", ex.getMessage(), ex);

            ApiResponseDto<CitizenUserRegistrationResponseDto> apiResponse =
                    ApiResponseDto.<CitizenUserRegistrationResponseDto>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Retrieve user profile information
     * GET /api/citizen-user/profile
     */
    @GetMapping("/profile")
    public ResponseEntity<ApiResponseDto<GetCitizenUserProfileResponseDto>> getUserProfile(
            @RequestParam("id") UUID id,
            @RequestParam("deviceId") String deviceId,
            @RequestParam("deviceType") String deviceType,
            @RequestParam("os") String os,
            @RequestParam("ipAddress") String ipAddress,
            @RequestParam("location") String location) {
        try {

            GetCitizenUserProfileRequestDto request = GetCitizenUserProfileRequestDto.builder()
                    .id(id)
                    .deviceId(deviceId)
                    .deviceType(deviceType)
                    .os(os)
                    .ipAddress(ipAddress)
                    .location(location)
                    .build();

            GetCitizenUserProfileResponseDto response = citizenUserService.getUserProfile(request);

            return ResponseEntity.ok(ApiResponseDto.<GetCitizenUserProfileResponseDto>builder()
                    .success(true)
                    .message("Profile retrieved successfully")
                    .data(response)
                    .timestamp(Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<GetCitizenUserProfileResponseDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<GetCitizenUserProfileResponseDto>builder()
                            .success(false)
                            .message("Failed to retrieve profile")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Retrieve all users profiles information
     * GET /api/citizen-user/profiles
     */
    @GetMapping("/profiles")
    public ResponseEntity<ApiResponseDto<List<GetCitizenUserProfileResponseDto>>> getAllUserProfiles() {
        log.info("Received request to fetch all citizen user profiles");

        try {
            List<GetCitizenUserProfileResponseDto> profiles = citizenUserService.getAllUserProfiles();

            ApiResponseDto<List<GetCitizenUserProfileResponseDto>> apiResponse =
                    ApiResponseDto.<List<GetCitizenUserProfileResponseDto>>builder()
                            .success(true)
                            .message("Citizen user profiles retrieved successfully")
                            .data(profiles)
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException ex) {
            log.error("Error while fetching all citizen user profiles: {}", ex.getMessage(), ex);

            ApiResponseDto<List<GetCitizenUserProfileResponseDto>> apiResponse =
                    ApiResponseDto.<List<GetCitizenUserProfileResponseDto>>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);

        } catch (Exception ex) {
            log.error("Unexpected error while fetching all citizen user profiles", ex);

            ApiResponseDto<List<GetCitizenUserProfileResponseDto>> apiResponse =
                    ApiResponseDto.<List<GetCitizenUserProfileResponseDto>>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Fetch all supporting documents for a given CitizenUser
     * GET /api/citizen-user/{id}/supporting-documents
     */
    @GetMapping("/{id}/supporting-documents")
    public ResponseEntity<ApiResponseDto<List<GetSupportingDocumentResponseDto>>> getSupportingDocuments(
            @PathVariable("id") UUID id) {

        log.info("Received request to fetch supporting documents for CitizenUser ID: {}", id);

        try {
            List<GetSupportingDocumentResponseDto> documents = citizenUserService.getSupportingDocument(id);

            ApiResponseDto<List<GetSupportingDocumentResponseDto>> apiResponse =
                    ApiResponseDto.<List<GetSupportingDocumentResponseDto>>builder()
                            .success(true)
                            .message("Supporting documents retrieved successfully")
                            .data(documents)
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException ex) {
            log.error("Error while retrieving supporting documents for CitizenUser ID: {} | ErrorCode: {} | Message: {}",
                    id, ex.getErrorCode(), ex.getMessage(), ex);

            ApiResponseDto<List<GetSupportingDocumentResponseDto>> errorResponse =
                    ApiResponseDto.<List<GetSupportingDocumentResponseDto>>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);

        } catch (Exception ex) {
            log.error("Unexpected error retrieving supporting documents for CitizenUser ID: {}", id, ex);

            ApiResponseDto<List<GetSupportingDocumentResponseDto>> errorResponse =
                    ApiResponseDto.<List<GetSupportingDocumentResponseDto>>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Upload profile photo
     * POST /api/citizen-user/{did}/profile-photo
     */
    @PostMapping(value = "/{did}/profile-photo", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponseDto<Map<String, String>>> uploadProfilePhoto(
            @PathVariable String did,
            @RequestParam("photo") MultipartFile photo) {
        try {

            String id = "did:sludi:" + did;
            // Validate file type and size
            validateImageFile(photo);

            citizenUserService.citizenUserProfilePhotoUpload(id, photo);

            return ResponseEntity.ok(ApiResponseDto.<Map<String, String>>builder()
                    .success(true)
                    .message("Profile photo uploaded successfully")
                    .timestamp(Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<Map<String, String>>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<Map<String, String>>builder()
                            .success(false)
                            .message("Failed to upload profile photo")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Update user profile information
     * PUT /api/did/{did}/profile
     */
    @PutMapping("/{did}/profile")
    public ResponseEntity<ApiResponseDto<GetCitizenUserProfileResponseDto>> updateUserProfile(
            @PathVariable String did,
            @Valid @RequestBody CitizenUserProfileUpdateRequestDto request) {

        try {
            String id = "did:sludi:" + did;

            GetCitizenUserProfileResponseDto response = citizenUserService.updateUserProfile(id, request);

            return ResponseEntity.ok(ApiResponseDto.<GetCitizenUserProfileResponseDto>builder()
                    .success(true)
                    .message("Profile updated successfully")
                    .data(response)
                    .timestamp(Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<GetCitizenUserProfileResponseDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<GetCitizenUserProfileResponseDto>builder()
                            .success(false)
                            .message("Failed to update profile")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Upload additional documents
     * POST /api/did/{did}/documents
     */
    @PostMapping(value = "/{did}/documents", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> uploadDocuments(
            @PathVariable String did,
            @Valid @RequestParam(value = "supportingDocuments") List<MultipartFile> files,
            @Valid @RequestParam(value = "documentTypes") List<String> documentTypes){

        try {
            String id = "did:sludi:" + did;

            // Attach uploaded files to DTO
            List<SupportingDocumentRequestDto> docs = new ArrayList<>();
            if (files != null && !files.isEmpty()) {
                for (int i = 0; i < files.size(); i++) {
                    MultipartFile file = files.get(i);
                    String docType = (documentTypes != null && documentTypes.size() > i)
                            ? documentTypes.get(i)
                            : "UNKNOWN";

                    docs.add(SupportingDocumentRequestDto.builder()
                            .name(file.getOriginalFilename())
                            .type(docType) // e.g., NIC, Birth Certificate
                            .file(file)
                            .build());
                }
            }

            CitizenUserProfileUpdateRequestDto request = CitizenUserProfileUpdateRequestDto.builder()
                    .newSupportingDocuments(docs)
                    .build();

            citizenUserService.updateUserProfile(id, request);

            return ResponseEntity.ok(ApiResponseDto.<Map<String, Object>>builder()
                    .success(true)
                    .message("Documents uploaded successfully")
                    .data(Map.of(
                            "documentsCount", docs.size(),
                            "uploadedAt", Instant.now()
                    ))
                    .timestamp(java.time.Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<Map<String, Object>>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<Map<String, Object>>builder()
                            .success(false)
                            .message("Failed to upload documents")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Validate image file for profile photo upload
     * @param file
     */
    private void validateImageFile(MultipartFile file) {
        if (file.isEmpty()) {
            throw new SludiException(ErrorCodes.EMPTY_IMAGE);
        }

        if (file.getSize() > 5 * 1024 * 1024) { // 5MB limit
            throw new SludiException(ErrorCodes.FILE_TOO_LARGE,"Image file too large. Maximum size is 5MB");
        }

        String contentType = file.getContentType();
        if (contentType == null ||
                (!contentType.equals("image/jpeg") && !contentType.equals("image/png") && !contentType.equals("image/jpg"))) {
            throw new SludiException(ErrorCodes.INVALID_FORMAT_IMAGE);
        }
    }

    /**
     * Validate document file for upload
     * @param file
     */
    private void validateDocumentFile(MultipartFile file) {
        if (file.isEmpty()) {
            throw new SludiException(ErrorCodes.MISSING_REQUIRED_FIELD);
        }

        if (file.getSize() > 10 * 1024 * 1024) { // 10MB limit
            throw new SludiException(ErrorCodes.FILE_TOO_LARGE, "Document file too large. Maximum size is 10MB");
        }

        String contentType = file.getContentType();
        if (contentType == null ||
                (!contentType.equals("application/pdf") &&
                        !contentType.equals("image/jpeg") &&
                        !contentType.equals("image/png") &&
                        !contentType.equals("image/jpg"))) {
            throw new SludiException(ErrorCodes.INVALID_FORMAT);
        }
    }
}
