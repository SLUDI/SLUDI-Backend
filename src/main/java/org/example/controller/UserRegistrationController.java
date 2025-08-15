package org.example.controller;

import jakarta.validation.Valid;
import org.example.dto.*;
import org.example.exception.ErrorCodes;
import org.example.service.UserRegistrationService;
import org.example.exception.SludiException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.UUID;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = "*")
public class UserRegistrationController {

    @Autowired
    private UserRegistrationService userRegistrationService;

    /**
     * Register new user and create DID
     * POST /api/users/register
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponseDto<UserRegistrationResponseDto>> registerUser(
            @Valid @RequestBody UserRegistrationRequestDto request) {

        try {
            UserRegistrationResponseDto response = userRegistrationService.registerUser(request);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponseDto.<UserRegistrationResponseDto>builder()
                            .success(true)
                            .message("User registered successfully")
                            .data(response)
                            .timestamp(java.time.Instant.now())
                            .build());

        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDto.<UserRegistrationResponseDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<UserRegistrationResponseDto>builder()
                            .success(false)
                            .message("Internal server error occurred")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(java.time.Instant.now())
                            .build());
        }
    }

    /**
     * Update user profile information
     * PUT /api/users/{userId}/profile
     */
    @PutMapping("/{userId}/profile")
    public ResponseEntity<ApiResponseDto<UserProfileResponseDto>> updateUserProfile(
            @PathVariable UUID userId,
            @Valid @RequestBody UserProfileUpdateRequestDto request,
            @RequestHeader(value = "Authorization", required = true) String authHeader) {

        try {
            // Extract user from JWT token for authorization
            validateAuthorization(authHeader, userId);

            UserProfileResponseDto response = userRegistrationService.updateUserProfile(userId, request);

            return ResponseEntity.ok(ApiResponseDto.<UserProfileResponseDto>builder()
                    .success(true)
                    .message("Profile updated successfully")
                    .data(response)
                    .timestamp(java.time.Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(getHttpStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<UserProfileResponseDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<UserProfileResponseDto>builder()
                            .success(false)
                            .message("Failed to update profile")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(java.time.Instant.now())
                            .build());
        }
    }

    /**
     * Retrieve user profile information
     * GET /api/users/{userId}/profile
     */
    @GetMapping("/{userId}/profile")
    public ResponseEntity<ApiResponseDto<UserProfileResponseDto>> getUserProfile(
            @PathVariable UUID userId,
            @RequestHeader(value = "Authorization", required = true) String authHeader) {

        try {
            String requesterDid = extractDidFromAuthHeader(authHeader);

            UserProfileResponseDto response = userRegistrationService.getUserProfile(userId, requesterDid);

            return ResponseEntity.ok(ApiResponseDto.<UserProfileResponseDto>builder()
                    .success(true)
                    .message("Profile retrieved successfully")
                    .data(response)
                    .timestamp(java.time.Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(getHttpStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<UserProfileResponseDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<UserProfileResponseDto>builder()
                            .success(false)
                            .message("Failed to retrieve profile")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(java.time.Instant.now())
                            .build());
        }
    }

    /**
     * Upload profile photo
     * POST /api/users/{userId}/profile-photo
     */
    @PostMapping("/{userId}/profile-photo")
    public ResponseEntity<ApiResponseDto<Map<String, String>>> uploadProfilePhoto(
            @PathVariable UUID userId,
            @RequestParam("photo") MultipartFile photo,
            @RequestHeader(value = "Authorization", required = true) String authHeader) {

        try {
            validateAuthorization(authHeader, userId);

            // Validate file type and size
            validateImageFile(photo);

            // Update profile with new photo
            UserProfileUpdateRequestDto request = UserProfileUpdateRequestDto.builder()
                    .profilePhoto(photo)
                    .build();

            UserProfileResponseDto response = userRegistrationService.updateUserProfile(userId, request);

            return ResponseEntity.ok(ApiResponseDto.<Map<String, String>>builder()
                    .success(true)
                    .message("Profile photo uploaded successfully")
                    .data(Map.of(
                            "photoHash", response.getProfilePhotoHash(),
                            "photoUrl", "/api/files/ipfs/" + response.getProfilePhotoHash()
                    ))
                    .timestamp(java.time.Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(getHttpStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<Map<String, String>>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<Map<String, String>>builder()
                            .success(false)
                            .message("Failed to upload profile photo")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(java.time.Instant.now())
                            .build());
        }
    }

    /**
     * Upload additional documents
     * POST /api/users/{userId}/documents
     */
    @PostMapping("/{userId}/documents")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> uploadDocuments(
            @PathVariable UUID userId,
            @RequestParam("documents") MultipartFile[] documents,
            @RequestParam(value = "category", required = false, defaultValue = "general") String category,
            @RequestHeader(value = "Authorization", required = true) String authHeader) {

        try {
            validateAuthorization(authHeader, userId);

            // Validate documents
            for (MultipartFile doc : documents) {
                validateDocumentFile(doc);
            }

            UserProfileUpdateRequestDto request = UserProfileUpdateRequestDto.builder()
                    .newDocuments(java.util.Arrays.asList(documents))
                    .build();

            userRegistrationService.updateUserProfile(userId, request);

            return ResponseEntity.ok(ApiResponseDto.<Map<String, Object>>builder()
                    .success(true)
                    .message("Documents uploaded successfully")
                    .data(Map.of(
                            "documentsCount", documents.length,
                            "category", category,
                            "uploadedAt", java.time.Instant.now()
                    ))
                    .timestamp(java.time.Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(getHttpStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<Map<String, Object>>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<Map<String, Object>>builder()
                            .success(false)
                            .message("Failed to upload documents")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(java.time.Instant.now())
                            .build());
        }
    }

    /**
     * Deactivate user account
     * POST /api/users/{userId}/deactivate
     */
    @PostMapping("/{userId}/deactivate")
    public ResponseEntity<ApiResponseDto<String>> deactivateUser(
            @PathVariable UUID userId,
            @RequestBody Map<String, String> requestBody,
            @RequestHeader(value = "Authorization", required = true) String authHeader) {

        try {
            // Only allow self-deactivation or admin deactivation
            validateDeactivationAuthorization(authHeader, userId);

            String reason = requestBody.getOrDefault("reason", "User requested deactivation");
            String result = userRegistrationService.deactivateUser(userId, reason);

            return ResponseEntity.ok(ApiResponseDto.<String>builder()
                    .success(true)
                    .message(result)
                    .data(result)
                    .timestamp(java.time.Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(getHttpStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<String>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<String>builder()
                            .success(false)
                            .message("Failed to deactivate user")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(java.time.Instant.now())
                            .build());
        }
    }

    /**
     * Check if user exists by identifier
     * GET /api/users/exists
     */
    @GetMapping("/exists")
    public ResponseEntity<ApiResponseDto<Map<String, Boolean>>> checkUserExists(
            @RequestParam String identifier,
            @RequestParam String type) { // email, nic, or did

        try {
            boolean exists;
            switch (type.toLowerCase()) {
                case "email":
                    exists = userRegistrationService.isCitizenUserExistsByEmail(identifier);
                    break;
                case "nic":
                    exists = userRegistrationService.isCitizenUserExistsByNic(identifier);
                    break;
                case "did":
                    exists = userRegistrationService.isCitizenUserExistsByDidId(identifier);
                    break;
                default:
                    throw new SludiException(ErrorCodes.INVALID_TYPE);
            }

            return ResponseEntity.ok(ApiResponseDto.<Map<String, Boolean>>builder()
                    .success(true)
                    .message("User existence check completed")
                    .data(Map.of("exists", exists))
                    .timestamp(java.time.Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDto.<Map<String, Boolean>>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<Map<String, Boolean>>builder()
                            .success(false)
                            .message("Failed to check user existence")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(java.time.Instant.now())
                            .build());
        }
    }

    /**
     * Get user statistics (for admin)
     * GET /api/users/statistics
     */
    @GetMapping("/statistics")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getUserStatistics(
            @RequestHeader(value = "Authorization", required = true) String authHeader) {

        try {
            validateAdminAuthorization(authHeader);

            Map<String, Object> stats = userRegistrationService.getUserStatistics();

            return ResponseEntity.ok(ApiResponseDto.<Map<String, Object>>builder()
                    .success(true)
                    .message("User statistics retrieved successfully")
                    .data(stats)
                    .timestamp(java.time.Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(getHttpStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<Map<String, Object>>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<Map<String, Object>>builder()
                            .success(false)
                            .message("Failed to retrieve statistics")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(java.time.Instant.now())
                            .build());
        }
    }

    private void validateAuthorization(String authHeader, UUID userId) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new SludiException(ErrorCodes.INVALID_AUTHRTIZATION_HEADER);
        }

        String token = authHeader.substring(7);
        UUID tokenUserId = extractUserIdFromToken(token);

        if (!tokenUserId.equals(userId)) {
            throw new SludiException(ErrorCodes.UNAUTHORIZED);
        }
    }

    private void validateDeactivationAuthorization(String authHeader, UUID userId) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new SludiException(ErrorCodes.INVALID_AUTHRTIZATION_HEADER);
        }

        String token = authHeader.substring(7);
        UUID tokenUserId = extractUserIdFromToken(token);
        String userRole = extractRoleFromToken(token);

        if (!tokenUserId.equals(userId) && !"ADMIN".equals(userRole)) {
            throw new SludiException(ErrorCodes.UNAUTHORIZED_USER, "Unauthorized to deactivate this user");
        }
    }

    private void validateAdminAuthorization(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new SludiException(ErrorCodes.INVALID_AUTHRTIZATION_HEADER);
        }

        String token = authHeader.substring(7);
        String userRole = extractRoleFromToken(token);

        if (!"ADMIN".equals(userRole)) {
            throw new SludiException(ErrorCodes.ADMIN_ONLY_OPERATION);
        }
    }

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

    private void validateDocumentFile(MultipartFile file) {
        if (file.isEmpty()) {
            throw new SludiException("Document file is required", "INVALID_FILE");
        }

        if (file.getSize() > 10 * 1024 * 1024) { // 10MB limit
            throw new SludiException("Document file too large. Maximum size is 10MB", "FILE_TOO_LARGE");
        }

        String contentType = file.getContentType();
        if (contentType == null ||
                (!contentType.equals("application/pdf") &&
                        !contentType.equals("image/jpeg") &&
                        !contentType.equals("image/png") &&
                        !contentType.equals("image/jpg"))) {
            throw new SludiException("Invalid document format. Only PDF and image files are allowed", "INVALID_FORMAT");
        }
    }

    private String extractDidFromAuthHeader(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new SludiException("Invalid authorization header", "UNAUTHORIZED");
        }

        String token = authHeader.substring(7);
        return extractDidFromToken(token);
    }

    private UUID extractUserIdFromToken(String token) {
        // Implementation would decode JWT token and extract user ID
        // This is a placeholder - implement actual JWT decoding
        try {
            // Decode JWT token and extract user ID
            return UUID.randomUUID(); // Placeholder
        } catch (Exception e) {
            throw new SludiException("Invalid token", "UNAUTHORIZED");
        }
    }

    private String extractDidFromToken(String token) {
        // Implementation would decode JWT token and extract DID
        // This is a placeholder - implement actual JWT decoding
        try {
            // Decode JWT token and extract DID
            return "did:sludi:placeholder"; // Placeholder
        } catch (Exception e) {
            throw new SludiException("Invalid token", "UNAUTHORIZED");
        }
    }

    private String extractRoleFromToken(String token) {
        // Implementation would decode JWT token and extract user role
        // This is a placeholder - implement actual JWT decoding
        try {
            // Decode JWT token and extract role
            return "USER"; // Placeholder
        } catch (Exception e) {
            throw new SludiException("Invalid token", "UNAUTHORIZED");
        }
    }

    private HttpStatus getHttpStatus(String errorCode) {
        switch (errorCode) {
            case "USER_NOT_FOUND":
            case "DID_NOT_FOUND":
                return HttpStatus.NOT_FOUND;
            case "UNAUTHORIZED":
                return HttpStatus.UNAUTHORIZED;
            case "USER_EXISTS":
            case "EMAIL_EXISTS":
            case "INVALID_INPUT":
            case "INVALID_NIC":
            case "MISSING_BIOMETRIC":
            case "MISSING_CONTACT":
            case "BIOMETRIC_INVALID":
            case "INVALID_FILE":
            case "FILE_TOO_LARGE":
            case "INVALID_FORMAT":
            case "INVALID_TYPE":
                return HttpStatus.BAD_REQUEST;
            case "USER_INACTIVE":
                return HttpStatus.FORBIDDEN;
            default:
                return HttpStatus.INTERNAL_SERVER_ERROR;
        }
    }
}

