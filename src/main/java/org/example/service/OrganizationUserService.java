package org.example.service;

import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.OrganizationUserRequestDto;
import org.example.dto.OrganizationUserResponseDto;
import org.example.dto.UserStatisticsResponseDto;
import org.example.entity.*;
import org.example.enums.UserStatus;
import org.example.enums.VerificationStatus;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.OrganizationOnboardingRepository;
import org.example.repository.OrganizationRepository;
import org.example.repository.OrganizationRoleRepository;
import org.example.repository.OrganizationUserRepository;
import org.hyperledger.fabric.client.Contract;
import org.hyperledger.fabric.client.Gateway;
import org.hyperledger.fabric.client.Network;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric_ca.sdk.Attribute;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class OrganizationUserService {

    private final OrganizationUserRepository userRepository;
    private final OrganizationRepository organizationRepository;
    private final OrganizationRoleRepository roleRepository;
    private final OrganizationOnboardingRepository onboardingRepository;
    private final HyperledgerService hyperledgerService;
    private final FabricCAService fabricCAService;
    private final PasswordEncoder passwordEncoder;
    private final MailService emailService;
    private final Gson gson = new Gson();

    public OrganizationUserService(
            OrganizationUserRepository userRepository,
            OrganizationRepository organizationRepository,
            OrganizationRoleRepository roleRepository,
            OrganizationOnboardingRepository onboardingRepository,
            HyperledgerService hyperledgerService,
            FabricCAService fabricCAService,
            PasswordEncoder passwordEncoder,
            MailService emailService
    ) {
        this.userRepository = userRepository;
        this.organizationRepository = organizationRepository;
        this.roleRepository = roleRepository;
        this.onboardingRepository = onboardingRepository;
        this.hyperledgerService = hyperledgerService;
        this.fabricCAService = fabricCAService;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
    }

    /**
     * Register a new organization user (employee)
     */
    @Transactional
    public OrganizationUserResponseDto registerUser(OrganizationUserRequestDto request) {
        log.info("Registering new user for organization: {}", request.getOrganizationId());

        // Validate organization
        Organization organization = organizationRepository.findById(request.getOrganizationId())
                .orElseThrow(() -> new SludiException(ErrorCodes.ORGANIZATION_NOT_FOUND));

        if (organization.getStatus() != Organization.OrganizationStatus.ACTIVE) {
            throw new SludiException(ErrorCodes.ORGANIZATION_NOT_ACTIVE);
        }

        // Check duplicates
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new SludiException(ErrorCodes.EMAIL_ALREADY_REGISTERED);
        }
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new SludiException(ErrorCodes.USER_NAME_ALREADY_TAKEN);
        }

        // Validate role
        OrganizationRole role = roleRepository.findById(request.getRoleId())
                .orElseThrow(() -> new SludiException(ErrorCodes.ROLE_NOT_FOUND));

        if (!role.getOrganization().getId().equals(organization.getId())) {
            throw new SludiException(ErrorCodes.ROLE_NOT_BELONG_THIS_ORGANIZATION);
        }

        if (!role.getIsActive()) {
            throw new SludiException(ErrorCodes.ROLE_IS_NOT_ACTIVE);
        }

        // Create user
        OrganizationUser user = OrganizationUser.builder()
                .organization(organization)
                .email(request.getEmail())
                .username(request.getUsername())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phone(request.getPhone())
                .did(request.getDid())
                .department(request.getDepartment())
                .designation(request.getDesignation())
                .jobTitle(request.getJobTitle())
                .assignedRole(role)
                .status(UserStatus.PENDING)
                .verificationStatus(VerificationStatus.NOT_STARTED)
                .createdBy(request.getCreatedBy())
                .build();

        user = userRepository.save(user);

        log.info("User registered successfully: {} (ID: {})", user.getUsername(), user.getId());

        // Send verification email
        try {
            emailService.sendUserVerificationEmail(user);
        } catch (Exception e) {
            log.error("Failed to send verification email", e);
        }

        return mapToUserResponse(user);
    }

    /**
     * Admin approves user and enrolls on blockchain
     */
    @Transactional
    public OrganizationUserResponseDto approveUser(Long userId, Long approvedBy) {
        log.info("Approving user ID: {}", userId);

        OrganizationUser user = userRepository.findById(userId)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        if (user.getStatus() != UserStatus.PENDING) {
            throw new SludiException(ErrorCodes.USER_NOT_PENDING_STATUS);
        }

        // Update user status
        user.setStatus(UserStatus.ACTIVE);
        user.setApprovedBy(approvedBy);
        user.setApprovedAt(LocalDateTime.now());
        user.setVerificationStatus(VerificationStatus.VERIFIED);

        user = userRepository.save(user);

        // Enroll user on blockchain
        try {
            enrollUserOnBlockchain(user);

            log.info("User approved and enrolled successfully: {}", user.getUsername());

            // Send activation email
            emailService.sendUserActivationEmail(user);

        } catch (Exception e) {
            log.error("Failed to enroll user on blockchain", e);

            // Rollback user activation
            user.setStatus(UserStatus.PENDING);
            user.setApprovedBy(null);
            user.setApprovedAt(null);
            userRepository.save(user);

            throw new SludiException(ErrorCodes.FAILED_TO_ENROLLED_BLOCKCHAIN, e.getMessage());
        }

        return mapToUserResponse(user);
    }

    /**
     * Enroll user on Hyperledger Fabric blockchain
     */
    private void enrollUserOnBlockchain(OrganizationUser user) throws Exception {
        log.info("Starting blockchain enrollment for user: {}", user.getUsername());

        OrganizationOnboarding onboarding = onboardingRepository
                .findByOrganizationId(user.getOrganization().getId())
                .orElseThrow(() -> new SludiException(ErrorCodes.ORGANIZATION_NOT_ONBOARD));

        String mspId = onboarding.getMspId();

        // Generate unique Fabric user ID
        String fabricUserId = generateFabricUserId(user);
        user.setFabricUserId(fabricUserId);

        log.info("Generated Fabric User ID: {} for MSP: {}", fabricUserId, mspId);

        // Step 1: Register user with Fabric CA
        String enrollmentSecret = registerWithFabricCA(user, mspId);
        user.setFabricEnrollmentId(enrollmentSecret);
        userRepository.save(user);

        log.info("User registered with Fabric CA, enrollment secret generated");

        // Step 2: Enroll user (get certificate)
        Enrollment enrollment = enrollUserWithCA(fabricUserId, enrollmentSecret, mspId);

        log.info("User enrollment certificate obtained");

        // Step 3: Store enrollment in wallet
        fabricCAService.storeUserEnrollment(mspId, fabricUserId, enrollment);

        log.info("User credentials stored in wallet");

        // Step 4: Register user on blockchain ledger
        log.info("Registering user on blockchain ledger: {}", user.getFabricUserId());
        String txId = hyperledgerService.registerUserOnBlockchain(user, mspId);

        log.info("User registered on blockchain with Tx ID: {}", txId);

        // Step 5: Update user record
        user.setIsEnrolledOnBlockchain(true);
        user.setEnrollmentDate(LocalDateTime.now());
        userRepository.save(user);

        log.info("Blockchain enrollment completed successfully for: {}", fabricUserId);
    }

    /**
     * Register user with Fabric CA
     */
    private String registerWithFabricCA(OrganizationUser user, String mspId) throws Exception {
        log.info("Registering user with Fabric CA: {} for MSP: {}", user.getUsername(), mspId);

        HFCAClient caClient = fabricCAService.getCaClient(mspId);
        User adminUser = fabricCAService.getAdminUser(mspId);

        // Create registration request
        RegistrationRequest registrationRequest = new RegistrationRequest(user.getFabricUserId());
        registrationRequest.setType("client"); // User type

        // Set affiliation (department)
        String affiliation = user.getDepartment() != null ?
                user.getDepartment().toLowerCase().replaceAll("[^a-z0-9]", "") :
                "default";
        registrationRequest.setAffiliation(affiliation);

        // Add attributes for role and permissions
        registrationRequest.addAttribute(new Attribute(
                "role",
                user.getAssignedRole().getRoleCode(),
                true // Include in certificate
        ));

        registrationRequest.addAttribute(new Attribute(
                "orgCode",
                user.getOrganization().getOrgCode(),
                true
        ));

        registrationRequest.addAttribute(new Attribute(
                "email",
                user.getEmail(),
                true
        ));

        // Set max enrollments
        registrationRequest.setMaxEnrollments(-1); // Unlimited re-enrollment

        // Register with CA using admin identity
        String enrollmentSecret = caClient.register(registrationRequest, adminUser);

        log.info("User registered with CA successfully, secret generated");

        return enrollmentSecret;
    }

    /**
     * Enroll user to get X.509 certificate
     */
    private Enrollment enrollUserWithCA(String fabricUserId, String secret, String mspId)
            throws Exception {
        log.info("Enrolling user to get certificate: {}", fabricUserId);

        HFCAClient caClient = fabricCAService.getCaClient(mspId);

        // Enroll user
        Enrollment enrollment = caClient.enroll(fabricUserId, secret);

        log.info("User certificate obtained successfully");

        return enrollment;
    }

    /**
     * Initialize organization roles from permission template
     */
    @Transactional
    public List<OrganizationRole> initializeOrganizationRoles(Long organizationId) {
        log.info("Initializing roles for organization: {}", organizationId);

        Organization organization = organizationRepository.findById(organizationId)
                .orElseThrow(() -> new SludiException(ErrorCodes.ORGANIZATION_NOT_FOUND));

        PermissionTemplate template = organization.getTemplate();
        if (template == null) {
            throw new SludiException(ErrorCodes.ORGANIZATION_HAS_NOT_TEMPLATE);
        }

        // Check if roles already exist
        if (roleRepository.existsByOrganizationId(organizationId)) {
            log.warn("Roles already initialized for organization: {}", organizationId);
            return roleRepository.findByOrganizationId(organizationId);
        }

        // Create roles from template's predefined roles
        List<OrganizationRole> roles = new ArrayList<>();

        for (PermissionTemplate.PredefinedRole predefinedRole : template.getPredefinedRoles()) {
            OrganizationRole role = OrganizationRole.builder()
                    .organization(organization)
                    .roleCode(predefinedRole.getRoleCode())
                    .description("Role created from template: " + template.getName())
                    .permissions(predefinedRole.getPermissions())
                    .isAdmin(predefinedRole.getIsAdmin())
                    .isActive(true)
                    .build();

            roles.add(roleRepository.save(role));
            log.info("Created role: {} ({})", role.getRoleCode(), role.getRoleCode());
        }

        log.info("Initialized {} roles for organization: {}", roles.size(), organization.getName());

        return roles;
    }

    /**
     * Get all users of an organization
     */
    @Transactional()
    public List<OrganizationUserResponseDto> getOrganizationUsers(
            Long organizationId,
            UserStatus status) {

        log.info("Fetching users for organization: {} with status: {}", organizationId, status);

        List<OrganizationUser> users;

        if (status != null) {
            users = userRepository.findByOrganizationIdAndStatus(organizationId, status);
        } else {
            users = userRepository.findByOrganizationId(organizationId);
        }

        return users.stream()
                .map(this::mapToUserResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get user details
     */
    @Transactional(readOnly = true)
    public OrganizationUserResponseDto getUserDetails(Long userId) {
        log.info("Fetching user details for ID: {}", userId);

        OrganizationUser user = userRepository.findById(userId)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        return mapToUserDetailsResponse(user);
    }

    /**
     * Update user role
     */
    @Transactional
    public OrganizationUserResponseDto updateUserRole(Long userId, Long newRoleId, Long updatedBy) {
        log.info("Updating role for user ID: {} to role ID: {}", userId, newRoleId);

        OrganizationUser user = userRepository.findById(userId)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        OrganizationRole newRole = roleRepository.findById(newRoleId)
                .orElseThrow(() -> new SludiException(ErrorCodes.ROLE_NOT_FOUND));

        // Validate role belongs to same organization
        if (!newRole.getOrganization().getId().equals(user.getOrganization().getId())) {
            throw new SludiException(ErrorCodes.ORGANIZATION_NOT_ONBOARD);
        }

        if (!newRole.getIsActive()) {
            throw new SludiException(ErrorCodes.ROLE_IS_NOT_ACTIVE);
        }

        OrganizationRole oldRole = user.getAssignedRole();
        user.setAssignedRole(newRole);
        user = userRepository.save(user);

        // Update role on blockchain if user is enrolled
        if (user.getIsEnrolledOnBlockchain()) {
            try {
                String txId = hyperledgerService.updateUserRoleOnBlockchain(user);
            } catch (Exception e) {
                log.error("Failed to update user role on blockchain", e);
            }
        } else {

        }

        log.info("User role updated successfully");

        return mapToUserResponse(user);
    }

    /**
     * Suspend user
     */
    @Transactional
    public void suspendUser(Long userId, String reason, Long suspendedBy) {
        log.info("Suspending user ID: {} for reason: {}", userId, reason);

        OrganizationUser user = userRepository.findById(userId)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        if (user.getStatus() == UserStatus.SUSPENDED) {
            throw new SludiException(ErrorCodes.USER_ALREADY_SUSPEND);
        }

        user.setStatus(UserStatus.SUSPENDED);
        user.setSuspendedBy(suspendedBy);
        user.setSuspendedAt(LocalDateTime.now());
        user.setSuspensionReason(reason);

        userRepository.save(user);

        // Revoke access on blockchain
        if (user.getIsEnrolledOnBlockchain()) {
            try {
                String txId = hyperledgerService.revokeUserAccessOnBlockchain(user, reason);
                log.info("");
            } catch (Exception e) {
                log.error("Failed to revoke user access on blockchain", e);
            }
        } else {

        }

        // Send suspension email
        try {
            emailService.sendUserSuspensionEmail(user, reason);
        } catch (Exception e) {
            log.error("Failed to send suspension email", e);
        }

        log.info("User suspended successfully");
    }



    /**
     * Reactivate suspended user
     */
    @Transactional
    public OrganizationUserResponseDto reactivateUser(Long userId, Long reactivatedBy) {
        log.info("Reactivating user ID: {}", userId);

        OrganizationUser user = userRepository.findById(userId)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        if (user.getStatus() != UserStatus.SUSPENDED) {
            throw new SludiException(ErrorCodes.USER_IS_NOT_SUSPENDED);
        }

        user.setStatus(UserStatus.ACTIVE);
        user.setSuspendedBy(null);
        user.setSuspendedAt(null);
        user.setSuspensionReason(null);

        user = userRepository.save(user);

        // Restore access on blockchain
        if (user.getIsEnrolledOnBlockchain()) {
            try {
                String txId = hyperledgerService.restoreUserAccessOnBlockchain(user);
            } catch (Exception e) {
                log.error("Failed to restore user access on blockchain", e);
            }
        } else {
        }

        // Send reactivation email
        try {
            emailService.sendUserReactivationEmail(user);
        } catch (Exception e) {
            log.error("Failed to send reactivation email", e);
        }

        log.info("User reactivated successfully");

        return mapToUserResponse(user);
    }

    /**
     * Verify user has specific permission
     */
    public boolean verifyUserPermission(String username, String permission) {
        log.debug("Verifying permission '{}' for user: {}", permission, username);

        Optional<OrganizationUser> userOpt = userRepository.findByUsername(username);

        if (userOpt.isEmpty()) {
            log.warn("User not found: {}", username);
            return false;
        }

        OrganizationUser user = userOpt.get();

        // Check if user is active
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("User is not active: {}", username);
            return false;
        }

        // Check role permissions
        List<String> rolePermissions = user.getAssignedRole().getPermissions();

        // Check if role has "ALL" permission (admin)
        if (rolePermissions.contains("ALL")) {
            return true;
        }

        // Check specific permission
        boolean hasPermission = rolePermissions.contains(permission);

        log.debug("Permission check result for {}: {}", username, hasPermission);
        return hasPermission;
    }

    /**
     * Get organization roles
     */
    @Transactional(readOnly = true)
    public List<OrganizationRole> getOrganizationRoles(Long organizationId, Boolean activeOnly) {
        log.info("Fetching roles for organization: {} (activeOnly: {})",
                organizationId, activeOnly);

        if (activeOnly != null && activeOnly) {
            return roleRepository.findActiveRolesByOrganizationId(organizationId);
        } else {
            return roleRepository.findByOrganizationId(organizationId);
        }
    }

//    /**
//     * Authenticate user
//     */
//    @Transactional
//    public AuthenticationResponse authenticateUser(String username, String password,
//                                                   String ipAddress) {
//        log.info("Authenticating user: {}", username);
//
//        OrganizationUser user = userRepository.findByUsername(username)
//                .orElseThrow(() -> new SludiException(ErrorCodes.INVALID_CREDENTIALS));
//
//        // Verify password
//        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
//            throw new SludiException(ErrorCodes.INVALID_CREDENTIALS);
//        }
//
//        // Check account status
//        if (user.getStatus() != UserStatus.ACTIVE) {
//            throw new SludiException(ErrorCodes.ACCOUNT_IS_NOT_ACTIVE);
//        }
//
//        log.info("User authenticated successfully: {}", username);
//
//        return AuthenticationResponse.builder()
//                .userId(user.getId())
//                .username(user.getUsername())
//                .email(user.getEmail())
//                .organizationId(user.getOrganization().getId())
//                .organizationName(user.getOrganization().getName())
//                .roleName(user.getAssignedRole().getRoleCode())
//                .permissions(user.getAssignedRole().getPermissions())
//                .fabricUserId(user.getFabricUserId())
//                .isEnrolledOnBlockchain(user.getIsEnrolledOnBlockchain())
//                .build();
//    }

    /**
     * Search users
     */
    @Transactional(readOnly = true)
    public List<OrganizationUserResponseDto> searchUsers(Long organizationId, String searchTerm) {
        log.info("Searching users in organization {} with term: {}", organizationId, searchTerm);

        List<OrganizationUser> users = userRepository.searchUsers(organizationId, searchTerm);

        return users.stream()
                .map(this::mapToUserResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get user statistics for organization
     */
    @Transactional(readOnly = true)
    public UserStatisticsResponseDto getOrganizationUserStatistics(Long organizationId) {
        log.info("Fetching user statistics for organization: {}", organizationId);

        long totalUsers = userRepository.countByOrganizationId(organizationId);
        long activeUsers = userRepository.countActiveUsersByOrganizationId(organizationId);

        List<OrganizationUser> pendingUsers = userRepository
                .findByOrganizationIdAndStatus(organizationId, UserStatus.PENDING);

        List<OrganizationUser> suspendedUsers = userRepository
                .findByOrganizationIdAndStatus(organizationId, UserStatus.SUSPENDED);

        List<OrganizationUser> enrolledUsers = userRepository
                .findByOrganizationId(organizationId).stream()
                .filter(OrganizationUser::getIsEnrolledOnBlockchain)
                .toList();

        return UserStatisticsResponseDto.builder()
                .totalUsers(totalUsers)
                .activeUsers(activeUsers)
                .pendingUsers(pendingUsers.size())
                .suspendedUsers(suspendedUsers.size())
                .enrolledOnBlockchain(enrolledUsers.size())
                .build();
    }

    /**
     * Reset user password
     */
    @Transactional
    public void resetPassword(Long userId, String newPassword, Long resetBy) {
        log.info("Resetting password for user ID: {}", userId);

        OrganizationUser user = userRepository.findById(userId)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Send email notification
        try {
            emailService.sendPasswordResetEmail(user, newPassword);
        } catch (Exception e) {
            log.error("Failed to send password reset email", e);
        }

        log.info("Password reset successfully");
    }

    /**
     * Delete user (soft delete - set to TERMINATED status)
     */
    @Transactional
    public void deleteUser(Long userId, Long deletedBy) {
        log.info("Deleting user ID: {}", userId);

        OrganizationUser user = userRepository.findById(userId)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        user.setStatus(UserStatus.DEACTIVATED);
        userRepository.save(user);

        // Revoke blockchain access
        if (user.getIsEnrolledOnBlockchain()) {
            try {
                hyperledgerService.revokeUserAccessOnBlockchain(user, "Account terminated");
            } catch (Exception e) {
                log.error("Failed to revoke blockchain access", e);
            }
        }

        log.info("User deleted successfully");
    }

    // Helper Methods

    /**
     * Generate unique Fabric user ID
     */
    private String generateFabricUserId(OrganizationUser user) {
        String orgPrefix = user.getOrganization().getOrgCode()
                .toLowerCase()
                .replaceAll("[^a-z0-9]", "");

        String username = user.getUsername()
                .toLowerCase()
                .replaceAll("[^a-z0-9]", "");

        return orgPrefix + "_" + username;
    }

    /**
     * Map entity to response DTO
     */
    private OrganizationUserResponseDto mapToUserResponse(OrganizationUser user) {
        return OrganizationUserResponseDto.builder()
                .userId(user.getId())
                .employeeId(user.getEmployeeId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phone(user.getPhone())
                .organizationId(user.getOrganization().getId())
                .organizationName(user.getOrganization().getName())
                .roleId(user.getAssignedRole().getId())
                .roleCode(user.getAssignedRole().getRoleCode())
                .department(user.getDepartment())
                .designation(user.getDesignation())
                .status(user.getStatus().name())
                .verificationStatus(user.getVerificationStatus().name())
                .isActive(user.getStatus().name())
                .isEnrolledOnBlockchain(user.getIsEnrolledOnBlockchain())
                .fabricUserId(user.getFabricUserId())
                .createdAt(user.getCreatedAt())
                .approvedAt(user.getApprovedAt())
                .build();
    }

    /**
     * Map entity to detailed response DTO
     */
    private OrganizationUserResponseDto mapToUserDetailsResponse(OrganizationUser user) {
        return OrganizationUserResponseDto.builder()
                .userId(user.getId())
                .employeeId(user.getEmployeeId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phone(user.getPhone())
                .did(user.getDid())
                .department(user.getDepartment())
                .designation(user.getDesignation())
                .jobTitle(user.getJobTitle())
                .organizationId(user.getOrganization().getId())
                .organizationName(user.getOrganization().getName())
                .organizationCode(user.getOrganization().getOrgCode())
                .roleId(user.getAssignedRole().getId())
                .roleCode(user.getAssignedRole().getRoleCode())
                .permissions(user.getAssignedRole().getPermissions())
                .status(user.getStatus().name())
                .verificationStatus(user.getVerificationStatus().name())
                .isEnrolledOnBlockchain(user.getIsEnrolledOnBlockchain())
                .fabricUserId(user.getFabricUserId())
                .enrollmentDate(user.getEnrollmentDate())
                .createdAt(user.getCreatedAt())
                .createdBy(user.getCreatedBy())
                .approvedAt(user.getApprovedAt())
                .approvedBy(user.getApprovedBy())
                .suspendedAt(user.getSuspendedAt())
                .suspendedBy(user.getSuspendedBy())
                .suspensionReason(user.getSuspensionReason())
                .build();
    }
}