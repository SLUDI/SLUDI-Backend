package org.example.controller;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.exception.ErrorCodes;
import org.example.service.DIDDocumentService;
import org.example.exception.SludiException;
import org.example.exception.HttpStatusHandler;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.UUID;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/did")
@CrossOrigin(origins = "*")
public class DIDDocumentController {
    
    private final DIDDocumentService didDocumentService;

    public DIDDocumentController(DIDDocumentService didDocumentService) {
        this.didDocumentService = didDocumentService;
    }

    /**
     * Register new user and create DID
     * POST /api/did/register
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponseDto<DIDCreateResponseDto>> createDID(
            @Valid @RequestBody DIDCreateRequestDto request) {

        log.info("Received user NIC: {} for DID create", request.getNic());

        try {
            DIDCreateResponseDto response = didDocumentService.createDID(request);

            ApiResponseDto<DIDCreateResponseDto> apiResponse = ApiResponseDto.<DIDCreateResponseDto>builder()
                    .success(true)
                    .message("User registered successfully")
                    .data(response)
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);

        } catch (SludiException ex) {
            log.error("User registration failed: {}", ex.getMessage(), ex);

            ApiResponseDto<DIDCreateResponseDto> apiResponse = ApiResponseDto.<DIDCreateResponseDto>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);

        } catch (Exception ex) {
            log.error("Unexpected error during registration: {}", ex.getMessage(), ex);

            ApiResponseDto<DIDCreateResponseDto> apiResponse = ApiResponseDto.<DIDCreateResponseDto>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Get user by DID
     * GET /api/did/{did}
     */
    @GetMapping("/{did}")
    public ResponseEntity<ApiResponseDto<DIDDocumentDto>> getUserByDid(
            @PathVariable String did) {
        try {
            String id = "did:sludi:" + did;
            DIDDocumentDto didDocument = didDocumentService.getDIDDocument(id);
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
     * Deactivate user account
     * POST /api/did/{userId}/deactivate
     */
    @PostMapping("/{userId}/deactivate")
    public ResponseEntity<ApiResponseDto<String>> deactivateUser(
            @PathVariable UUID userId,
            @RequestBody Map<String, String> requestBody,
            @RequestHeader(value = "Authorization", required = true) String authHeader) {

        try {
            String reason = requestBody.getOrDefault("reason", "User requested deactivation");
            String result = didDocumentService.deactivateDID(userId, reason);

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
     * Deactivate user account
     * POST /api/did/delete
     */
    @DeleteMapping("/delete/{did}")
    public ResponseEntity<ApiResponseDto<String>> deactivateUser(@PathVariable String did) {

        try {
            String result = didDocumentService.deleteDID(did);

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
                            .message("Failed to delete DID")
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

