package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.entity.OrganizationRole;
import org.example.enums.UserStatus;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.service.OrganizationUserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/organization-users")
@CrossOrigin(origins = "*")
public class OrganizationUserController {

    private final OrganizationUserService userService;

    public OrganizationUserController(OrganizationUserService userService) {
        this.userService = userService;
    }

    /**
     * Register new organization user (employee)
     * POST /api/organization-users/register
     */
    @PostMapping("/register")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<OrganizationUserResponseDto>> registerUser(
            @Valid @RequestBody OrganizationUserRequestDto request) {

        log.info("Received user registration request for organization: {}", request.getOrganizationId());

        try {
            String userName = getCurrentUsername();

            OrganizationUserResponseDto response = userService.registerEmployeeUser(request, userName);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(true)
                    .message("User registered successfully. Pending approval.")
                    .data(response)
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);

        } catch (SludiException ex) {
            log.error("User registration failed: {}", ex.getMessage(), ex);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);

        } catch (Exception ex) {
            log.error("Unexpected error during registration: {}", ex.getMessage(), ex);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Approve pending user and enroll on blockchain
     * POST /api/organization-users/{userId}/approve
     */
    @PostMapping("/{userId}/approve")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<OrganizationUserResponseDto>> approveUser(
            @PathVariable Long userId) {

        try {
            String userName = getCurrentUsername();
            log.info("Approving user ID: {} by admin ID: {}", userId, userName);
            OrganizationUserResponseDto response = userService.approveEmployeeUser(userId, userName);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(true)
                    .message("User approved and enrolled on blockchain successfully")
                    .data(response)
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException ex) {
            log.error("User approval failed: {}", ex.getMessage(), ex);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);

        } catch (Exception ex) {
            log.error("Unexpected error during approval: {}", ex.getMessage(), ex);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Get all users of an organization
     * GET /api/organization-users/organization/{organizationId}
     */
    @GetMapping("/organization/{organizationId}")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<List<OrganizationUserResponseDto>>> getOrganizationUsers(
            @PathVariable Long organizationId,
            @RequestParam(required = false) UserStatus status) {

        log.info("Fetching users for organization: {} with status: {}", organizationId, status);

        try {
            String userName = getCurrentUsername();
            List<OrganizationUserResponseDto> users = userService.getOrganizationUsers(organizationId, status, userName);

            ApiResponseDto<List<OrganizationUserResponseDto>> apiResponse = ApiResponseDto.<List<OrganizationUserResponseDto>>builder()
                    .success(true)
                    .message("Users fetched successfully")
                    .data(users)
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (Exception ex) {
            log.error("Error fetching users: {}", ex.getMessage(), ex);

            ApiResponseDto<List<OrganizationUserResponseDto>> apiResponse = ApiResponseDto.<List<OrganizationUserResponseDto>>builder()
                    .success(false)
                    .message("Failed to fetch users")
                    .errorCode("FETCH_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Get user details by ID
     * GET /api/organization-users/{userId}
     */
    @GetMapping("/{userId}")
    public ResponseEntity<ApiResponseDto<OrganizationUserResponseDto>> getUserDetails(
            @PathVariable Long userId) {

        log.info("Fetching details for user ID: {}", userId);

        try {
            OrganizationUserResponseDto user = userService.getUserDetails(userId);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(true)
                    .message("User details fetched successfully")
                    .data(user)
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException ex) {
            log.error("User not found: {}", ex.getMessage(), ex);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(apiResponse);

        } catch (Exception ex) {
            log.error("Error fetching user details: {}", ex.getMessage(), ex);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Update user role
     * PUT /api/organization-users/{userId}/role
     */
    @PutMapping("/{userId}/role")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<OrganizationUserResponseDto>> updateUserRole(
            @PathVariable Long userId,
            @RequestParam Long newRoleId) {

        log.info("Updating role for user ID: {} to role ID: {}", userId, newRoleId);

        try {
            String userName = getCurrentUsername();

            OrganizationUserResponseDto response = userService.updateUserRole(userId, newRoleId, userName);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(true)
                    .message("User role updated successfully")
                    .data(response)
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException ex) {
            log.error("Role update failed: {}", ex.getMessage(), ex);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);

        } catch (Exception ex) {
            log.error("Unexpected error during role update: {}", ex.getMessage(), ex);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Suspend user
     * POST /api/organization-users/{userId}/suspend
     */
    @PostMapping("/{userId}/suspend")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<Void>> suspendUser(
            @PathVariable Long userId,
            @RequestParam String reason) {

        try {
            String suspendedBy = getCurrentUsername();
            log.info("Suspending user ID: {} by admin ID: {}", userId, suspendedBy);
            userService.suspendUser(userId, reason, suspendedBy);

            ApiResponseDto<Void> apiResponse = ApiResponseDto.<Void>builder()
                    .success(true)
                    .message("User suspended successfully")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException ex) {
            log.error("User suspension failed: {}", ex.getMessage(), ex);

            ApiResponseDto<Void> apiResponse = ApiResponseDto.<Void>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);

        } catch (Exception ex) {
            log.error("Unexpected error during suspension: {}", ex.getMessage(), ex);

            ApiResponseDto<Void> apiResponse = ApiResponseDto.<Void>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Reactivate suspended user
     * POST /api/organization-users/{userId}/reactivate
     */
    @PostMapping("/{userId}/reactivate")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<OrganizationUserResponseDto>> reactivateUser(
            @PathVariable Long userId) {

        try {
            String reactivatedBy = getCurrentUsername();
            log.info("Reactivating user ID: {} by admin ID: {}", userId, reactivatedBy);
            OrganizationUserResponseDto response = userService.reactivateUser(userId, reactivatedBy);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(true)
                    .message("User reactivated successfully")
                    .data(response)
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException ex) {
            log.error("User reactivation failed: {}", ex.getMessage(), ex);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);

        } catch (Exception ex) {
            log.error("Unexpected error during reactivation: {}", ex.getMessage(), ex);

            ApiResponseDto<OrganizationUserResponseDto> apiResponse = ApiResponseDto.<OrganizationUserResponseDto>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Verify user permission
     * GET /api/organization-users/verify-permission
     */
    @GetMapping("/verify-permission")
    public ResponseEntity<ApiResponseDto<Boolean>> verifyUserPermission(
            @RequestParam String username,
            @RequestParam String permission) {

        log.info("Verifying permission '{}' for user: {}", permission, username);

        try {
            boolean hasPermission = userService.verifyUserPermission(username, permission);

            ApiResponseDto<Boolean> apiResponse = ApiResponseDto.<Boolean>builder()
                    .success(true)
                    .message(hasPermission ? "User has permission" : "User does not have permission")
                    .data(hasPermission)
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (Exception ex) {
            log.error("Error verifying permission: {}", ex.getMessage(), ex);

            ApiResponseDto<Boolean> apiResponse = ApiResponseDto.<Boolean>builder()
                    .success(false)
                    .message("Failed to verify permission")
                    .errorCode("VERIFICATION_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Initialize organization roles from template
     * POST /api/organization-users/organization/{organizationId}/roles/initialize
     */
    @PostMapping("/organization/{organizationId}/roles/initialize")
    public ResponseEntity<ApiResponseDto<List<OrganizationRole>>> initializeOrganizationRoles(
            @PathVariable Long organizationId) {

        log.info("Initializing roles for organization: {}", organizationId);

        try {
            List<OrganizationRole> roles = userService.initializeOrganizationRoles(organizationId);

            ApiResponseDto<List<OrganizationRole>> apiResponse = ApiResponseDto.<List<OrganizationRole>>builder()
                    .success(true)
                    .message("Organization roles initialized successfully")
                    .data(roles)
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);

        } catch (SludiException ex) {
            log.error("Role initialization failed: {}", ex.getMessage(), ex);

            ApiResponseDto<List<OrganizationRole>> apiResponse = ApiResponseDto.<List<OrganizationRole>>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);

        } catch (Exception ex) {
            log.error("Unexpected error during role initialization: {}", ex.getMessage(), ex);

            ApiResponseDto<List<OrganizationRole>> apiResponse = ApiResponseDto.<List<OrganizationRole>>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Get organization roles
     * GET /api/organization-users/organization/{organizationId}/roles
     */
    @GetMapping("/organization/{organizationId}/roles")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<List<OrganizationRoleDto>>> getOrganizationRoles(
            @PathVariable Long organizationId,
            @RequestParam(required = false) Boolean activeOnly) {

        log.info("Fetching roles for organization: {}", organizationId);

        try {
            String userName = getCurrentUsername();
            List<OrganizationRoleDto> roles = userService.getOrganizationRoles(organizationId, activeOnly, userName);

            ApiResponseDto<List<OrganizationRoleDto>> apiResponse = ApiResponseDto.<List<OrganizationRoleDto>>builder()
                    .success(true)
                    .message("Roles fetched successfully")
                    .data(roles)
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (Exception ex) {
            log.error("Error fetching roles: {}", ex.getMessage(), ex);

            ApiResponseDto<List<OrganizationRoleDto>> apiResponse = ApiResponseDto.<List<OrganizationRoleDto>>builder()
                    .success(false)
                    .message("Failed to fetch roles")
                    .errorCode("FETCH_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Search users
     * GET /api/organization-users/organization/{organizationId}/search
     */
    @GetMapping("/organization/{organizationId}/search")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<List<OrganizationUserResponseDto>>> searchUsers(
            @PathVariable Long organizationId,
            @RequestParam String searchTerm) {

        log.info("Searching users in organization {} with term: {}", organizationId, searchTerm);

        try {
            String userName = getCurrentUsername();
            List<OrganizationUserResponseDto> users = userService.searchUsers(organizationId, searchTerm, userName);

            ApiResponseDto<List<OrganizationUserResponseDto>> apiResponse = ApiResponseDto.<List<OrganizationUserResponseDto>>builder()
                    .success(true)
                    .message("Search completed successfully")
                    .data(users)
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (Exception ex) {
            log.error("Error searching users: {}", ex.getMessage(), ex);

            ApiResponseDto<List<OrganizationUserResponseDto>> apiResponse = ApiResponseDto.<List<OrganizationUserResponseDto>>builder()
                    .success(false)
                    .message("Search failed")
                    .errorCode("SEARCH_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Get organization user statistics
     * GET /api/organization-users/organization/{organizationId}/statistics
     */
    @GetMapping("/organization/{organizationId}/statistics")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<UserStatisticsResponseDto>> getOrganizationUserStatistics(
            @PathVariable Long organizationId) {

        log.info("Fetching user statistics for organization: {}", organizationId);

        try {
            String userName = getCurrentUsername();
            UserStatisticsResponseDto statistics = userService.getOrganizationUserStatistics(organizationId, userName);

            ApiResponseDto<UserStatisticsResponseDto> apiResponse = ApiResponseDto.<UserStatisticsResponseDto>builder()
                    .success(true)
                    .message("Statistics fetched successfully")
                    .data(statistics)
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (Exception ex) {
            log.error("Error fetching statistics: {}", ex.getMessage(), ex);

            ApiResponseDto<UserStatisticsResponseDto> apiResponse = ApiResponseDto.<UserStatisticsResponseDto>builder()
                    .success(false)
                    .message("Failed to fetch statistics")
                    .errorCode("FETCH_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Reset user password
     * POST /api/organization-users/{userId}/reset-password
     */
    @PostMapping("/{userId}/reset-password")
    public ResponseEntity<ApiResponseDto<Void>> resetPassword(
            @PathVariable Long userId,
            @RequestParam String newPassword,
            @RequestParam Long resetBy) {

        log.info("Resetting password for user ID: {}", userId);

        try {
            userService.resetPassword(userId, newPassword, resetBy);

            ApiResponseDto<Void> apiResponse = ApiResponseDto.<Void>builder()
                    .success(true)
                    .message("Password reset successfully")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException ex) {
            log.error("Password reset failed: {}", ex.getMessage(), ex);

            ApiResponseDto<Void> apiResponse = ApiResponseDto.<Void>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);

        } catch (Exception ex) {
            log.error("Unexpected error during password reset: {}", ex.getMessage(), ex);

            ApiResponseDto<Void> apiResponse = ApiResponseDto.<Void>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Delete user (soft delete)
     * DELETE /api/organization-users/{userId}
     */
    @DeleteMapping("/{userId}")
    public ResponseEntity<ApiResponseDto<Void>> deleteUser(
            @PathVariable Long userId,
            @RequestParam Long deletedBy) {

        log.info("Deleting user ID: {}", userId);

        try {
            userService.deleteUser(userId, deletedBy);

            ApiResponseDto<Void> apiResponse = ApiResponseDto.<Void>builder()
                    .success(true)
                    .message("User deleted successfully")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException ex) {
            log.error("User deletion failed: {}", ex.getMessage(), ex);

            ApiResponseDto<Void> apiResponse = ApiResponseDto.<Void>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);

        } catch (Exception ex) {
            log.error("Unexpected error during deletion: {}", ex.getMessage(), ex);

            ApiResponseDto<Void> apiResponse = ApiResponseDto.<Void>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Login organization user
     * POST /api/organization-users/auth/login
     */
    @PostMapping("/auth/login")
    public ResponseEntity<ApiResponseDto<OrganizationLoginResponseDto>> login(
            @Valid @RequestBody OrganizationLoginRequestDto request) {

        log.info("Login request for user: {}", request.getUsernameOrEmail());

        try {
            OrganizationLoginResponseDto response = userService.login(request);

            ApiResponseDto<OrganizationLoginResponseDto> apiResponse =
                    ApiResponseDto.<OrganizationLoginResponseDto>builder()
                            .success(true)
                            .message("Login successful")
                            .data(response)
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException ex) {
            log.error("Login failed for {}: {}", request.getUsernameOrEmail(), ex.getMessage());

            ApiResponseDto<OrganizationLoginResponseDto> apiResponse =
                    ApiResponseDto.<OrganizationLoginResponseDto>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(apiResponse);

        } catch (Exception ex) {
            log.error("Unexpected error during login: {}", ex.getMessage(), ex);

            ApiResponseDto<OrganizationLoginResponseDto> apiResponse =
                    ApiResponseDto.<OrganizationLoginResponseDto>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Refresh access token
     * POST /api/organization-users/auth/refresh
     */
    @PostMapping("/auth/refresh")
    public ResponseEntity<ApiResponseDto<RefreshTokenResponseDto>> refreshToken(
            @Valid @RequestBody RefreshTokenRequestDto request) {

        log.info("Token refresh request");

        try {
            RefreshTokenResponseDto response = userService.refreshToken(request.getRefreshToken());

            ApiResponseDto<RefreshTokenResponseDto> apiResponse =
                    ApiResponseDto.<RefreshTokenResponseDto>builder()
                            .success(true)
                            .message("Token refreshed successfully")
                            .data(response)
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException ex) {
            log.error("Token refresh failed: {}", ex.getMessage());

            ApiResponseDto<RefreshTokenResponseDto> apiResponse =
                    ApiResponseDto.<RefreshTokenResponseDto>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(apiResponse);

        } catch (Exception ex) {
            log.error("Unexpected error during token refresh: {}", ex.getMessage(), ex);

            ApiResponseDto<RefreshTokenResponseDto> apiResponse =
                    ApiResponseDto.<RefreshTokenResponseDto>builder()
                            .success(false)
                            .message("Internal server error")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
        }
    }

    /**
     * Change password for authenticated user
     * POST /api/organization-users/auth/change-password
     */
    @PostMapping("/auth/change-password")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<Void>> changePassword(
            @Valid @RequestBody ChangePasswordRequestDto request) {

        log.info("Password change request");

        try {
            String username = getCurrentUsername();
            userService.changePassword(username, request);

            ApiResponseDto<Void> apiResponse = ApiResponseDto.<Void>builder()
                    .success(true)
                    .message("Password changed successfully")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException ex) {
            log.error("Password change failed: {}", ex.getMessage());

            ApiResponseDto<Void> apiResponse = ApiResponseDto.<Void>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiResponse);

        } catch (Exception ex) {
            log.error("Unexpected error during password change: {}", ex.getMessage(), ex);

            ApiResponseDto<Void> apiResponse = ApiResponseDto.<Void>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiResponse);
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