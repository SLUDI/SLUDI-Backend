package org.example.controller;

import jakarta.validation.Valid;
import org.example.dto.*;
import org.example.exception.ErrorCodes;
import org.example.service.DIDDocumentService;
import org.example.exception.SludiException;
import org.example.exception.HttpStatusHandler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.UUID;
import java.util.Map;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/did")
@CrossOrigin(origins = "*")
public class DIDDocumentController {

    private static final Logger LOGGER = Logger.getLogger(DIDDocumentController.class.getName());

    @Autowired
    private DIDDocumentService didDocumentService;

    /**
     * Register new user and create DID
     * POST /api/did/register
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponseDto<UserRegistrationResponseDto>> registerUser(
            @Valid @RequestBody UserRegistrationRequestDto request){

        try {
            UserRegistrationResponseDto response = didDocumentService.registerUser(request);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponseDto.<UserRegistrationResponseDto>builder()
                            .success(true)
                            .message("User registered successfully")
                            .data(response)
                            .timestamp(java.time.Instant.now())
                            .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<UserRegistrationResponseDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(java.time.Instant.now())
                            .build());
        }
    }

    /**
     * Get user by DID
     * GET /api/did/did/{did}
     */
    @GetMapping("/did/{did}")
    public ResponseEntity<ApiResponseDto<DIDDocumentDto>> getUserByDid(
            @PathVariable String did) {
        try {
            DIDDocumentDto didDocument = didDocumentService.getDIDDocument(did);
            return ResponseEntity.ok(ApiResponseDto.<DIDDocumentDto>builder()
                    .success(true)
                    .message("User retrieved successfully")
                    .data(didDocument)
                    .timestamp(java.time.Instant.now())
                    .build());
        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<DIDDocumentDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<DIDDocumentDto>builder()
                            .success(false)
                            .message("Failed to retrieve user by DID")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(java.time.Instant.now())
                            .build());
        }
    }

    /**
     * Update user profile information
     * PUT /api/did/{userId}/profile
     */
    @PutMapping("/{userId}/profile")
    public ResponseEntity<ApiResponseDto<UserProfileResponseDto>> updateUserProfile(
            @PathVariable UUID userId,
            @Valid @RequestBody UserProfileUpdateRequestDto request,
            @RequestHeader(value = "Authorization", required = true) String authHeader) {

        try {
            // Extract user from JWT token for authorization
            validateAuthorization(authHeader, userId);

            UserProfileResponseDto response = didDocumentService.updateUserProfile(userId, request);

            return ResponseEntity.ok(ApiResponseDto.<UserProfileResponseDto>builder()
                    .success(true)
                    .message("Profile updated successfully")
                    .data(response)
                    .timestamp(java.time.Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
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
     * GET /api/did/{userId}/profile
     */
    @GetMapping("/{userId}/profile")
    public ResponseEntity<ApiResponseDto<UserProfileResponseDto>> getUserProfile(
            @PathVariable UUID userId,
            @RequestHeader(value = "Authorization", required = true) String authHeader) {

        try {
            String requesterDid = extractDidFromAuthHeader(authHeader);

            UserProfileResponseDto response = didDocumentService.getUserProfile(userId, requesterDid);

            return ResponseEntity.ok(ApiResponseDto.<UserProfileResponseDto>builder()
                    .success(true)
                    .message("Profile retrieved successfully")
                    .data(response)
                    .timestamp(java.time.Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
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
     * POST /api/did/{userId}/profile-photo
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

            UserProfileResponseDto response = didDocumentService.updateUserProfile(userId, request);

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
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
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
     * POST /api/did/{userId}/documents
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

            didDocumentService.updateUserProfile(userId, request);

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
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
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
     * POST /api/did/{userId}/deactivate
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
            String result = didDocumentService.deactivateUser(userId, reason);

            return ResponseEntity.ok(ApiResponseDto.<String>builder()
                    .success(true)
                    .message(result)
                    .data(result)
                    .timestamp(java.time.Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
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
     * GET /api/did/exists
     */
    @GetMapping("/exists")
    public ResponseEntity<ApiResponseDto<Map<String, Boolean>>> checkUserExists(
            @RequestParam String identifier,
            @RequestParam String type) { // email, nic, or did

        try {
            boolean exists;
            switch (type.toLowerCase()) {
                case "email":
                    exists = didDocumentService.isCitizenUserExistsByEmail(identifier);
                    break;
                case "nic":
                    exists = didDocumentService.isCitizenUserExistsByNic(identifier);
                    break;
                case "did":
                    exists = didDocumentService.isCitizenUserExistsByDidId(identifier);
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
     * GET /api/did/statistics
     */
    @GetMapping("/statistics")
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> getUserStatistics(
            @RequestHeader(value = "Authorization", required = true) String authHeader) {

        try {
            validateAdminAuthorization(authHeader);

            Map<String, Object> stats = didDocumentService.getUserStatistics();

            return ResponseEntity.ok(ApiResponseDto.<Map<String, Object>>builder()
                    .success(true)
                    .message("User statistics retrieved successfully")
                    .data(stats)
                    .timestamp(java.time.Instant.now())
                    .build());

        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
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

    /**
     * Validate authorization header and extract user ID
     * @param authHeader
     * @param userId
     */
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

    /**
     * Validate deactivation authorization
     * @param authHeader
     * @param userId
     */
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

    /**
     * Validate admin authorization
     * @param authHeader
     */
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

    /**
     * Extract DID from Authorization header
     * @param authHeader
     * @return DID
     */
    private String extractDidFromAuthHeader(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new SludiException(ErrorCodes.INVALID_AUTHRTIZATION_HEADER);
        }

        String token = authHeader.substring(7);
        return extractDidFromToken(token);
    }

    /**
     * Extract user ID, DID, and role from JWT token
     * These methods are placeholders and should be implemented with actual JWT decoding logic
     */
    private UUID extractUserIdFromToken(String token) {
        try {
            // Decode JWT token and extract user ID
            return UUID.randomUUID(); // Placeholder
        } catch (Exception e) {
            throw new SludiException(ErrorCodes.TOKEN_INVALID);
        }
    }

    private String extractDidFromToken(String token) {
        try {
            // Decode JWT token and extract DID
            return "did:sludi:placeholder"; // Placeholder
        } catch (Exception e) {
            throw new SludiException(ErrorCodes.TOKEN_INVALID);
        }
    }

    private String extractRoleFromToken(String token) {
        try {
            // Decode JWT token and extract role
            return "USER"; // Placeholder
        } catch (Exception e) {
            throw new SludiException(ErrorCodes.TOKEN_INVALID);
        }
    }
}

