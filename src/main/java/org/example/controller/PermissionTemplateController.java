package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

import org.example.dto.ApiResponseDto;
import org.example.dto.CreatePermissionTemplateRequest;
import org.example.dto.PermissionTemplateResponse;
import org.example.service.PermissionTemplateService;
import org.example.exception.SludiException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;

/**
 * Controller for managing permission templates.
 * Provides endpoints for creating and retrieving permission templates.
 */
@RestController
@RequestMapping("/api/permission-templates")
@Slf4j
@Validated
@CrossOrigin(origins = "*")
public class PermissionTemplateController {

    private final PermissionTemplateService permissionTemplateService;

    public PermissionTemplateController(PermissionTemplateService permissionTemplateService) {
        this.permissionTemplateService = permissionTemplateService;
    }

    /**
     * Creates a new permission template.
     *
     * @param request the request containing permission template details
     * @return ResponseEntity containing the created permission template
     */
    @PostMapping("/create")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<PermissionTemplateResponse>> createPermissionTemplate(
            @Valid @RequestBody CreatePermissionTemplateRequest request) {
        log.info("Creating permission template: {}", request.getTemplateCode());

        try {
            String userName = getCurrentUsername();
            PermissionTemplateResponse response = permissionTemplateService.addPermissionTemplate(request);

            log.info("Successfully created permission template with ID: {}", response.getId());

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponseDto.<PermissionTemplateResponse>builder()
                            .success(true)
                            .message("Permission template created successfully")
                            .data(response)
                            .timestamp(Instant.now())
                            .build());

        } catch (SludiException ex) {
            log.error("Permission template creation failed: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDto.<PermissionTemplateResponse>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception ex) {
            log.error("Unexpected error during permission template creation: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<PermissionTemplateResponse>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Retrieves all permission templates, optionally filtered by active status.
     *
     * @param isActive optional parameter to filter templates by active status
     * @return ResponseEntity containing the list of permission templates
     */
    @GetMapping("/get-all")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<List<PermissionTemplateResponse>>> getAllPermissionTemplates(
            @RequestParam(required = false) Boolean isActive) {
        log.info("Retrieving permission templates with active status filter: {}", isActive);

        try {
            List<PermissionTemplateResponse> responses = permissionTemplateService.getAllTemplates(isActive);

            log.info("Successfully retrieved {} permission templates", responses.size());

            return ResponseEntity.status(HttpStatus.OK)
                    .body(ApiResponseDto.<List<PermissionTemplateResponse>>builder()
                            .success(true)
                            .message("Permission templates retrieved successfully")
                            .data(responses)
                            .timestamp(Instant.now())
                            .build());

        } catch (SludiException ex) {
            log.error("Failed to retrieve permission templates: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDto.<List<PermissionTemplateResponse>>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception ex) {
            log.error("Unexpected error while retrieving permission templates: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<List<PermissionTemplateResponse>>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Retrieves a permission template by its ID.
     *
     * @param id the ID of the permission template
     * @return ResponseEntity containing the permission template
     */
    @GetMapping("/{id}")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<PermissionTemplateResponse>> getPermissionTemplateById(
            @PathVariable Long id) {
        log.info("Retrieving permission template with ID: {}", id);

        try {
            PermissionTemplateResponse response = permissionTemplateService.getTemplate(id);

            log.info("Successfully retrieved permission template with ID: {}", id);

            return ResponseEntity.status(HttpStatus.OK)
                    .body(ApiResponseDto.<PermissionTemplateResponse>builder()
                            .success(true)
                            .message("Permission template retrieved successfully")
                            .data(response)
                            .timestamp(Instant.now())
                            .build());

        } catch (SludiException ex) {
            log.error("Failed to retrieve permission template with ID {}: {}", id, ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponseDto.<PermissionTemplateResponse>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception ex) {
            log.error("Unexpected error while retrieving permission template with ID {}: {}", id, ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<PermissionTemplateResponse>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Helper method to get the current username from security context.
     *
     * @return the username of the authenticated user
     */
    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null ? authentication.getName() : "system";
    }
}