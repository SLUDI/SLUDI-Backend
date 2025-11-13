package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

import org.example.dto.*;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.service.OrganizationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;

@RestController
@Slf4j
@RequestMapping("api/organization")
@CrossOrigin(origins = "*")
public class OrganizationController {

    private final OrganizationService organizationService;

    public OrganizationController(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    /**
     * Create new organization
     */
    @PostMapping("/create-organization")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<OrganizationResponse>> createOrganization(
            @Valid @RequestBody CreateOrganizationRequest request) {
        log.info("Creating organization: {}", request.getName());

        try {
            String userName = getCurrentUsername();
            OrganizationResponse response = organizationService.createOrganization(request, userName);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(true)
                            .message("Organization registered successfully")
                            .data(response)
                            .timestamp(Instant.now())
                            .build());

        } catch (SludiException ex) {
            log.error("Organization creation failed: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception ex) {
            log.error("Unexpected error during organization creation: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Update organization details (Super Admin only)
     */
    @PutMapping("/update-organization/{id}")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<OrganizationResponse>> updateOrganization(
            @PathVariable Long id,
            @Valid @RequestBody UpdateOrganizationRequest request) {
        log.info("Updating organization: {}", request.getName());

        try {
            String userName = getCurrentUsername();
            OrganizationResponse response = organizationService.updateOrganization(id, request, userName);

            return ResponseEntity.status(HttpStatus.OK)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(true)
                            .message("Organization updated successfully")
                            .data(response)
                            .timestamp(Instant.now())
                            .build());

        } catch (SludiException ex) {
            log.error("Organization update failed: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception ex) {
            log.error("Unexpected error during organization update: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Fetch all organizations
     */
    @GetMapping("/")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<List<OrganizationResponse>>> getAllOrganizations() {
        log.info("Fetching all organizations");

        try {
            String userName = getCurrentUsername();
            List<OrganizationResponse> organizationResponses = organizationService.getAllOrganizations(userName);

            return ResponseEntity.status(HttpStatus.OK)
                    .body(ApiResponseDto.<List<OrganizationResponse>>builder()
                            .success(true)
                            .message("Organizations fetched successfully")
                            .data(organizationResponses)
                            .timestamp(Instant.now())
                            .build());

        } catch (SludiException ex) {
            log.error("Failed to fetch organizations: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDto.<List<OrganizationResponse>>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception ex) {
            log.error("Unexpected error while fetching organizations: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<List<OrganizationResponse>>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Fetch organization details by organization id
     * @param id
     */
    @GetMapping("/get-organization/{id}")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<OrganizationDetailResponse>> getOrganizationById(
            @PathVariable Long id) {
        log.info("Fetching organization {}", id);

        try {
            String userName = getCurrentUsername();
            OrganizationDetailResponse response = organizationService.getOrganizationDetails(id, userName);

            return ResponseEntity.status(HttpStatus.OK)
                    .body(ApiResponseDto.<OrganizationDetailResponse>builder()
                            .success(true)
                            .message("Organization fetched successfully")
                            .data(response)
                            .timestamp(Instant.now())
                            .build());

        } catch (SludiException ex) {
            log.error("Failed to fetch organization: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDto.<OrganizationDetailResponse>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception ex) {
            log.error("Unexpected error while fetching organization: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<OrganizationDetailResponse>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Approve a organization
     * @param id
     */
    @PutMapping("/approve/{id}")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<OrganizationResponse>> approveOrganization(
            @PathVariable Long id) {
        log.info("Approving organization: {}", id);

        try {
            String userName = getCurrentUsername();
            OrganizationResponse response = organizationService.approveOrganization(id, userName);

            return ResponseEntity.status(HttpStatus.OK)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(true)
                            .message("Approved organization successfully")
                            .data(response)
                            .timestamp(Instant.now())
                            .build());

        } catch (SludiException ex) {
            log.error("Organization approval failed: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception ex) {
            log.error("Unexpected error during organization approval: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Customize organization permissions (Super Admin only)
     */
    @PutMapping("/{id}/permissions")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<OrganizationDetailResponse>> customizePermissions(
            @PathVariable Long id,
            @Valid @RequestBody CustomPermissionsRequest request) {

        log.info("Customizing permissions for organization ID: {}", id);

        try {
            String userName = getCurrentUsername();
            OrganizationDetailResponse response = organizationService.customizePermissions(
                    id, request, userName);

            return ResponseEntity.status(HttpStatus.OK)
                    .body(ApiResponseDto.<OrganizationDetailResponse>builder()
                            .success(true)
                            .message("Permissions customized successfully")
                            .data(response)
                            .timestamp(Instant.now())
                            .build());

        } catch (SludiException ex) {
            log.error("Permission customization failed: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDto.<OrganizationDetailResponse>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception ex) {
            log.error("Unexpected error during permission customization: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<OrganizationDetailResponse>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Suspend organization
     */
    @PutMapping("/{id}/suspend")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<OrganizationResponse>> suspendOrganization(
            @PathVariable Long id,
            @Valid @RequestBody SuspendOrganizationRequest request) {

        log.info("Suspending organization ID: {}", id);

        try {
            String userName = getCurrentUsername();
            OrganizationResponse response = organizationService.suspendOrganization(
                    id, request.getReason(), userName);

            return ResponseEntity.status(HttpStatus.OK)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(true)
                            .message("Organization suspended successfully")
                            .data(response)
                            .timestamp(Instant.now())
                            .build());

        } catch (SludiException ex) {
            log.error("Organization suspension failed: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception ex) {
            log.error("Unexpected error during organization suspension: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Reactivate suspended organization (Super Admin only)
     */
    @PutMapping("/{id}/reactivate")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<OrganizationResponse>> reactivateOrganization(@PathVariable Long id) {

        log.info("Reactivating organization ID: {}", id);

        try {
            String userName = getCurrentUsername();
            OrganizationResponse response = organizationService.reactivateOrganization(id, userName);

            return ResponseEntity.status(HttpStatus.OK)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(true)
                            .message("Organization reactivated successfully")
                            .data(response)
                            .timestamp(Instant.now())
                            .build());

        } catch (SludiException ex) {
            log.error("Organization reactivation failed: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception ex) {
            log.error("Unexpected error during organization reactivation: {}", ex.getMessage(), ex);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<OrganizationResponse>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    // Helper method to get current authenticated username
    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new SludiException(ErrorCodes.AUTH_FAILED);
        }
        return authentication.getName();
    }
}