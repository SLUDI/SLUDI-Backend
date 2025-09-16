package org.example.controller;

import jakarta.validation.Valid;
import org.example.dto.*;
import org.example.exception.ErrorCodes;
import org.example.exception.HttpStatusHandler;
import org.example.exception.SludiException;
import org.example.service.CitizenUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/citizen-user")
@CrossOrigin(origins = "*")
public class CitizenUserController {

    private static final Logger LOGGER = Logger.getLogger(CitizenUserController.class.getName());

    @Autowired
    private CitizenUserService citizenUserService;

    /**
     * Register new user and create DID
     * POST /api/citizen-user/register
     */
    @PostMapping(value = "/register", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponseDto<CitizenUserRegistrationResponseDto>> registerUser(
            @Valid @RequestParam CitizenUserRegistrationRequestDto request,
            @Valid @RequestParam(value = "supportingDocuments") List<MultipartFile> files,
            @Valid @RequestParam(value = "documentTypes") List<String> documentTypes) {

        LOGGER.info("Received user registration NIC: " + request.getPersonalInfo().getNic());

        try {

            // Attach uploaded files to DTO
            if (files != null && !files.isEmpty()) {
                List<SupportingDocument> docs = new ArrayList<>();
                for (int i = 0; i < files.size(); i++) {
                    MultipartFile file = files.get(i);
                    String docType = (documentTypes != null && documentTypes.size() > i)
                            ? documentTypes.get(i)
                            : "UNKNOWN";

                    docs.add(SupportingDocument.builder()
                            .name(file.getOriginalFilename())
                            .type(docType) // e.g., NIC, Birth Certificate
                            .file(file)
                            .build());
                }
                request.setSupportingDocuments(docs);
            }

            CitizenUserRegistrationResponseDto response = citizenUserService.registerCitizenUser(request);

            ApiResponseDto<CitizenUserRegistrationResponseDto> apiResponse = ApiResponseDto.<CitizenUserRegistrationResponseDto>builder()
                    .success(true)
                    .message("User registered successfully")
                    .data(response)
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);

        } catch (SludiException ex) {
            LOGGER.log(Level.SEVERE,"User registration failed: " + ex.getMessage(), ex);

            ApiResponseDto<CitizenUserRegistrationResponseDto> apiResponse = ApiResponseDto.<CitizenUserRegistrationResponseDto>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);

        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, "Unexpected error during registration: " + ex.getMessage(), ex);

            ApiResponseDto<CitizenUserRegistrationResponseDto> apiResponse = ApiResponseDto.<CitizenUserRegistrationResponseDto>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
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
     * Retrieve user profile information
     * GET /api/did/{did}/profile
     */
    @GetMapping("/{did}/profile")
    public ResponseEntity<ApiResponseDto<CitizenUserProfileResponseDto>> getUserProfile(
            @PathVariable String did) {

        try {
            String id = "did:sludi:" + did;

            CitizenUserProfileResponseDto response = citizenUserService.getUserProfile(id);

            return ResponseEntity.ok(ApiResponseDto.<CitizenUserProfileResponseDto>builder()
                    .success(true)
                    .message("Profile retrieved successfully")
                    .data(response)
                    .timestamp(Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<CitizenUserProfileResponseDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<CitizenUserProfileResponseDto>builder()
                            .success(false)
                            .message("Failed to retrieve profile")
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
    public ResponseEntity<ApiResponseDto<CitizenUserProfileResponseDto>> updateUserProfile(
            @PathVariable String did,
            @Valid @RequestBody CitizenUserProfileUpdateRequestDto request) {

        try {
            String id = "did:sludi:" + did;

            CitizenUserProfileResponseDto response = citizenUserService.updateUserProfile(id, request);

            return ResponseEntity.ok(ApiResponseDto.<CitizenUserProfileResponseDto>builder()
                    .success(true)
                    .message("Profile updated successfully")
                    .data(response)
                    .timestamp(Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<CitizenUserProfileResponseDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<CitizenUserProfileResponseDto>builder()
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
            @RequestParam("documents") MultipartFile[] documents,
            @RequestParam(value = "category", required = false, defaultValue = "general") String category){

        try {
            String id = "did:sludi:" + did;
            // Validate documents
            for (MultipartFile doc : documents) {
                validateDocumentFile(doc);
            }

            CitizenUserProfileUpdateRequestDto request = CitizenUserProfileUpdateRequestDto.builder()
                    .newDocuments(java.util.Arrays.asList(documents))
                    .build();

            citizenUserService.updateUserProfile(id, request);

            return ResponseEntity.ok(ApiResponseDto.<Map<String, Object>>builder()
                    .success(true)
                    .message("Documents uploaded successfully")
                    .data(Map.of(
                            "documentsCount", documents.length,
                            "category", category,
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
