package org.example.controller;

import jakarta.validation.Valid;
import org.example.dto.ApiResponseDto;
import org.example.dto.UserProfileResponseDto;
import org.example.dto.UserProfileUpdateRequestDto;
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
import java.util.Map;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/citizen-user")
@CrossOrigin(origins = "*")
public class CitizenUserController {

    private static final Logger LOGGER = Logger.getLogger(CitizenUserController.class.getName());

    @Autowired
    private CitizenUserService citizenUserService;

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
    public ResponseEntity<ApiResponseDto<UserProfileResponseDto>> getUserProfile(
            @PathVariable String did) {

        try {
            String id = "did:sludi:" + did;

            UserProfileResponseDto response = citizenUserService.getUserProfile(id);

            return ResponseEntity.ok(ApiResponseDto.<UserProfileResponseDto>builder()
                    .success(true)
                    .message("Profile retrieved successfully")
                    .data(response)
                    .timestamp(Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<UserProfileResponseDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<UserProfileResponseDto>builder()
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
    public ResponseEntity<ApiResponseDto<UserProfileResponseDto>> updateUserProfile(
            @PathVariable String did,
            @Valid @RequestBody UserProfileUpdateRequestDto request) {

        try {
            String id = "did:sludi:" + did;

            UserProfileResponseDto response = citizenUserService.updateUserProfile(id, request);

            return ResponseEntity.ok(ApiResponseDto.<UserProfileResponseDto>builder()
                    .success(true)
                    .message("Profile updated successfully")
                    .data(response)
                    .timestamp(Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<UserProfileResponseDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<UserProfileResponseDto>builder()
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

            UserProfileUpdateRequestDto request = UserProfileUpdateRequestDto.builder()
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
