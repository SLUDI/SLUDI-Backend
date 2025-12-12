package org.example.service;

import com.google.gson.Gson;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.entity.*;
import org.example.enums.OrganizationStatus;
import org.example.enums.PredefinedRole;
import org.example.enums.UserStatus;
import org.example.enums.VerificationStatus;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.OrganizationOnboardingRepository;
import org.example.repository.OrganizationRepository;
import org.example.repository.OrganizationRoleRepository;
import org.example.repository.OrganizationUserRepository;
import org.example.security.OrganizationJwtService;
import org.example.utils.EmployeeIdGenerator;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric_ca.sdk.Attribute;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class OrganizationUserService {

    @Value("${security.jwt.access.expiration-time}")
    private long jwtExpiration;

    private final OrganizationUserRepository userRepository;
    private final OrganizationRepository organizationRepository;
    private final OrganizationRoleRepository roleRepository;
    private final OrganizationOnboardingRepository onboardingRepository;
    private final HyperledgerService hyperledgerService;
    private final FabricCAService fabricCAService;
    private final PasswordEncoder passwordEncoder;
    private final MailService emailService;
    private final EmployeeIdGenerator employeeIdGenerator;
    private final OrganizationJwtService jwtService;
    private final Gson gson = new Gson();

    public OrganizationUserService(
            OrganizationUserRepository userRepository,
            OrganizationRepository organizationRepository,
            OrganizationRoleRepository roleRepository,
            OrganizationOnboardingRepository onboardingRepository,
            HyperledgerService hyperledgerService,
            FabricCAService fabricCAService,
            PasswordEncoder passwordEncoder,
            MailService emailService,
            EmployeeIdGenerator employeeIdGenerator,
            OrganizationJwtService jwtService
    ) {
        this.userRepository = userRepository;
        this.organizationRepository = organizationRepository;
        this.roleRepository = roleRepository;
        this.onboardingRepository = onboardingRepository;
        this.hyperledgerService = hyperledgerService;
        this.fabricCAService = fabricCAService;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.employeeIdGenerator = employeeIdGenerator;
        this.jwtService = jwtService;
    }

    /**
     * Register a new organization user (admin)
     */
    public OrganizationUserResponseDto registerAdminUser(OrganizationUserRequestDto request) {
        return registerUser(request);
    }

    /**
     * Register a new organization user (employee)
     */
    public OrganizationUserResponseDto registerEmployeeUser(OrganizationUserRequestDto request, String userName) {
        // Find user
        OrganizationUser user = userRepository.findByUsername(userName)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to create organization user
        if (!verifyUserPermission(userName, "organization:user:create")) {
            log.warn("User {} attempted to create organization user without permission", userName);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to create organization user", userName);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }
        request.setCreatedBy(userName);
        return registerUser(request);
    }

    /**
     * Register a new organization user
     */
    @Transactional
    private OrganizationUserResponseDto registerUser(OrganizationUserRequestDto request) {
        log.info("Registering new user for organization: {}", request.getOrganizationId());

        // Validate organization
        Organization organization = organizationRepository.findById(request.getOrganizationId())
                .orElseThrow(() -> new SludiException(ErrorCodes.ORGANIZATION_NOT_FOUND));

        if (organization.getStatus() != OrganizationStatus.ACTIVE) {
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

        String employeeId = employeeIdGenerator.generateCode(organization);

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
                .employeeId(employeeId)
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
     * Approve a new organization user (admin)
     */
    public OrganizationUserResponseDto approveAdminUser(Long userId, String approvedBy) {
        return approveUser(userId, approvedBy);
    }

    /**
     * Approve a new organization user (employee)
     */
    public OrganizationUserResponseDto approveEmployeeUser(Long userId, String approvedBy) {
        // Find user
        OrganizationUser user = userRepository.findByUsername(approvedBy)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to create organization user
        if (!verifyUserPermission(approvedBy, "organization:user:approve")) {
            log.warn("User {} attempted to approve organization user without permission", approvedBy);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to approve organization user", approvedBy);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }
        return approveUser(userId, approvedBy);
    }

    /**
     * Admin approves user and enrolls on blockchain
     */
    @Transactional
    private OrganizationUserResponseDto approveUser(Long userId, String approvedBy) {
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
     * Enroll user on Hyperledger Fabric blockchain (Node.js style)
     */
    private void enrollUserOnBlockchain(OrganizationUser user) {
        log.info("Starting blockchain enrollment for user: {}", user.getUsername());

        try {
            OrganizationOnboarding onboarding = onboardingRepository
                    .findByOrganizationId(user.getOrganization().getId())
                    .orElseThrow(() -> new SludiException(ErrorCodes.ORGANIZATION_NOT_ONBOARD));

            String mspId = onboarding.getMspId();
            String orgShortName = mspId.replace("MSP", "").toLowerCase();

            // Verify admin is enrolled
            User adminUser = fabricCAService.getAdminUser(mspId);
            log.info("Admin identity confirmed for MSP: {}", mspId);

            // Generate unique Fabric user ID
            String fabricUserId = generateFabricUserId(user);
            user.setFabricUserId(fabricUserId);
            log.info("Generated Fabric User ID: {}", fabricUserId);

            // Register user with CA
            String enrollmentSecret = registerUserWithCA(user, mspId, orgShortName);
            user.setFabricEnrollmentId(enrollmentSecret);
            userRepository.save(user);
            log.info("User registered with CA - Secret: {}", enrollmentSecret);

            // Enroll user to get certificate
            Enrollment enrollment = enrollUserWithCA(fabricUserId, enrollmentSecret, mspId);
            if (enrollment == null) {
                throw new IllegalStateException("Fabric enrollment returned null");
            }
            log.info("User certificate obtained successfully");

            // Store credentials in wallet
            fabricCAService.storeUserEnrollment(mspId, fabricUserId, enrollment);
            log.info("User credentials stored in wallet");

            // Register user on blockchain ledger
            String txId = hyperledgerService.registerUserOnBlockchain(user, mspId);
            log.info("User registered on blockchain with Tx ID: {}", txId);

            // Update user record
            user.setIsEnrolledOnBlockchain(true);
            user.setEnrollmentDate(LocalDateTime.now());
            userRepository.save(user);

            log.info("Blockchain enrollment completed successfully");

        } catch (Exception e) {
            log.error("Failed to enroll user on blockchain: {}", e.getMessage(), e);
            throw new SludiException(ErrorCodes.BLOCKCHAIN_ENROLMENT_FAILED, e.getMessage());
        }
    }

    /**
     * Register user with Fabric CA
     */
    private String registerUserWithCA(OrganizationUser user, String mspId, String orgShortName) throws Exception {
        log.info("Registering user with Fabric CA: {} for MSP: {}", user.getUsername(), mspId);

        // Get CA client and admin identity
        HFCAClient caClient = fabricCAService.getCaClient(mspId);
        User adminUser = fabricCAService.getAdminUser(mspId);

        // The admin's affiliation must match for authorization to work
        String affiliation = "";

        log.info("Using affiliation: {} (from admin user)", affiliation);

        RegistrationRequest registrationRequest = new RegistrationRequest(
                user.getFabricUserId(),
                affiliation
        );

        registrationRequest.setType("client");
        registrationRequest.setMaxEnrollments(-1); // Unlimited re-enrollment

        String requestedAffiliation = orgShortName + ".department1";

        // Add attributes for certificate
        registrationRequest.addAttribute(new Attribute("role", user.getAssignedRole().getRoleCode(), true));
        registrationRequest.addAttribute(new Attribute("orgCode", user.getOrganization().getOrgCode(), true));
        registrationRequest.addAttribute(new Attribute("email", user.getEmail(), true));
        registrationRequest.addAttribute(new Attribute("requestedAffiliation", requestedAffiliation, false));

        try {
            // Register user and get enrollment secret
            String enrollmentSecret = caClient.register(registrationRequest, adminUser);
            log.info("User {} successfully registered with CA. Enrollment secret generated.",
                    user.getUsername());
            return enrollmentSecret;
        } catch (Exception e) {
            log.error("Failed to register user '{}' on CA for MSP '{}': {}",
                    user.getUsername(), mspId, e.getMessage());
            throw new SludiException(ErrorCodes.BLOCKCHAIN_USER_REGISTRATION_FAILED, e.getMessage());
        }
    }

    /**
     * Enroll user to get X.509 certificate
     */
    private Enrollment enrollUserWithCA(String fabricUserId, String secret, String mspId) throws Exception {
        log.info("Enrolling user to get certificate: {}", fabricUserId);

        HFCAClient caClient = fabricCAService.getCaClient(mspId);

        // Enroll user with secret (Node.js pattern)
        Enrollment enrollment = caClient.enroll(fabricUserId, secret);

        log.info("User certificate obtained successfully for: {}", fabricUserId);

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

        // Create roles from template's predefined role instances
        List<OrganizationRole> roles = new ArrayList<>();

        for (PredefinedRole.RoleInstance roleInstance : template.getPredefinedRoles()) {
            OrganizationRole role = OrganizationRole.builder()
                    .organization(organization)
                    .roleCode(roleInstance.getRoleCode())
                    .description(String.format("%s - Role created from template: %s",
                            roleInstance.getDescription(), template.getName()))
                    .permissions(roleInstance.getPermissions())
                    .isAdmin(roleInstance.getIsAdmin())
                    .isActive(true)
                    .build();

            roles.add(roleRepository.save(role));
            log.info("Created role: {} ({}) with {} permissions",
                    role.getRoleCode(),
                    roleInstance.getDescription(),
                    role.getPermissions().size());
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
            UserStatus status,
            String userName) {

        log.info("Fetching users for organization: {} with status: {}", organizationId, status);

        // Find user
        OrganizationUser user = userRepository.findByUsername(userName)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to view organization user
        if (!verifyUserPermission(userName, "organization:user:view")) {
            log.warn("User {} attempted to view organization user without permission", user);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to view organization user", user);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

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
    public OrganizationUserResponseDto updateUserRole(Long userId, Long newRoleId, String updatedBy) {
        log.info("Updating role for user ID: {} to role ID: {}", userId, newRoleId);

        // Find user
        OrganizationUser adminUser = userRepository.findByUsername(updatedBy)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to update organization user
        if (!verifyUserPermission(updatedBy, "organization:user:update")) {
            log.warn("User {} attempted to update organization user without permission", adminUser);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (adminUser.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to update organization user", adminUser);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

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
        }

        log.info("User role updated successfully");

        return mapToUserResponse(user);
    }

    /**
     * Suspend user
     */
    @Transactional
    public void suspendUser(Long userId, String reason, String suspendedBy) {
        log.info("Suspending user ID: {} for reason: {}", userId, reason);

        // Find user
        OrganizationUser adminUser = userRepository.findByUsername(suspendedBy)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to suspend organization user
        if (!verifyUserPermission(suspendedBy, "organization:user:suspend")) {
            log.warn("User {} attempted to suspend organization user without permission", adminUser);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (adminUser.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to suspend organization user", adminUser);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

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
                log.info("User access revoked on blockchain");
            } catch (Exception e) {
                log.error("Failed to revoke user access on blockchain", e);
            }
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
    public OrganizationUserResponseDto reactivateUser(Long userId, String reactivatedBy) {
        log.info("Reactivating user ID: {}", userId);

        // Find user
        OrganizationUser adminUser = userRepository.findByUsername(reactivatedBy)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to reactive organization user
        if (!verifyUserPermission(reactivatedBy, "organization:user:reactive")) {
            log.warn("User {} attempted to reactive organization user without permission", adminUser);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (adminUser.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to reactive organization user", adminUser);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

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
    public List<OrganizationRoleDto> getOrganizationRoles(Long organizationId, Boolean activeOnly, String userName) {
        log.info("Fetching roles for organization: {} (activeOnly: {})", organizationId, activeOnly);

        OrganizationUser adminUser = userRepository.findByUsername(userName)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        if (!verifyUserPermission(userName, "organization:user:view")) {
            log.warn("User {} attempted to view organization user without permission", adminUser);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        if (adminUser.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to view organization user", adminUser);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

        List<OrganizationRole> roles = (activeOnly != null && activeOnly)
                ? roleRepository.findActiveRolesByOrganizationId(organizationId)
                : roleRepository.findByOrganizationId(organizationId);

        // Convert to DTOs
        return roles.stream()
                .map(role -> OrganizationRoleDto.builder()
                        .id(role.getId())
                        .roleCode(role.getRoleCode())
                        .description(role.getDescription())
                        .permissions(role.getPermissions())
                        .isAdmin(role.getIsAdmin())
                        .isActive(role.getIsActive())
                        .createdAt(role.getCreatedAt())
                        .updatedAt(role.getUpdatedAt())
                        .build())
                .collect(Collectors.toList());
    }

    /**
     * Search users
     */
    @Transactional(readOnly = true)
    public List<OrganizationUserResponseDto> searchUsers(Long organizationId, String searchTerm, String userName) {
        log.info("Searching users in organization {} with term: {}", organizationId, searchTerm);

        // Find user
        OrganizationUser adminUser = userRepository.findByUsername(userName)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to view organization user
        if (!verifyUserPermission(userName, "organization:user:view")) {
            log.warn("User {} attempted to view organization user without permission", adminUser);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (adminUser.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to view organization user", adminUser);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

        List<OrganizationUser> users = userRepository.searchUsers(organizationId, searchTerm);

        return users.stream()
                .map(this::mapToUserResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get user statistics for organization
     */
    @Transactional(readOnly = true)
    public UserStatisticsResponseDto getOrganizationUserStatistics(Long organizationId, String userName) {
        log.info("Fetching user statistics for organization: {}", organizationId);

        // Find user
        OrganizationUser adminUser = userRepository.findByUsername(userName)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to view organization user
        if (!verifyUserPermission(userName, "organization:user:view")) {
            log.warn("User {} attempted to view organization user without permission", adminUser);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (adminUser.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to view organization user", adminUser);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

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

    @Transactional(readOnly = true)
    public UserStatisticsResponseDto getOrganizationsUserStatistics() {
        log.info("Fetching user statistics");

        long totalUsers = userRepository.count();
        long activeUsers = userRepository.countAllActiveUsers();

        List<OrganizationUser> pendingUsers = userRepository
                .findByStatus(UserStatus.PENDING);

        List<OrganizationUser> suspendedUsers = userRepository
                .findByStatus(UserStatus.SUSPENDED);

        List<OrganizationUser> enrolledUsers = userRepository
                .findEnrolledUsers().stream()
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

    /**
     * Login organization user
     */
    @Transactional
    public OrganizationLoginResponseDto login(OrganizationLoginRequestDto request) {
        log.info("Login attempt for user: {}", request.getUsernameOrEmail());

        // Find user by username or email
        OrganizationUser user = userRepository.findByUsername(request.getUsernameOrEmail())
                .orElseGet(() -> userRepository.findByEmail(request.getUsernameOrEmail())
                        .orElseThrow(() -> new SludiException(ErrorCodes.INVALID_CREDENTIALS)));

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            log.warn("Invalid password for user: {}", request.getUsernameOrEmail());
            throw new SludiException(ErrorCodes.INVALID_CREDENTIALS);
        }

        // Check user status
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user login attempt: {} (Status: {})",
                    user.getUsername(), user.getStatus());
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

        // Check organization status
        if (user.getOrganization().getStatus() != OrganizationStatus.ACTIVE) {
            log.warn("User {} attempted login but organization {} is not active",
                    user.getUsername(), user.getOrganization().getName());
            throw new SludiException(ErrorCodes.ORGANIZATION_NOT_ACTIVE);
        }

        // Generate tokens
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        log.info("User logged in successfully: {} (Organization: {})",
                user.getUsername(), user.getOrganization().getName());

        return OrganizationLoginResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtExpiration)
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .employeeId(user.getEmployeeId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .organizationId(user.getOrganization().getId())
                .organizationName(user.getOrganization().getName())
                .organizationCode(user.getOrganization().getOrgCode())
                .roleId(user.getAssignedRole().getId())
                .roleCode(user.getAssignedRole().getRoleCode())
                .isAdmin(user.getAssignedRole().getIsAdmin())
                .permissions(user.getAssignedRole().getPermissions())
                .loginTime(LocalDateTime.now())
                .build();
    }

    /**
     * Refresh access token
     */
    @Transactional
    public RefreshTokenResponseDto refreshToken(String refreshToken) {
        log.info("Refreshing access token");

        try {
            // Validate refresh token
            Claims claims = jwtService.validateToken(refreshToken);
            String username = claims.getSubject();

            // Find user
            OrganizationUser user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

            // Check user is still active
            if (user.getStatus() != UserStatus.ACTIVE) {
                throw new SludiException(ErrorCodes.USER_INACTIVE);
            }

            // Generate new access token
            String newAccessToken = jwtService.refreshAccessToken(refreshToken, user);

            log.info("Access token refreshed for user: {}", username);

            return RefreshTokenResponseDto.builder()
                    .accessToken(newAccessToken)
                    .tokenType("Bearer")
                    .expiresIn(jwtExpiration)
                    .build();

        } catch (SludiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage(), e);
            throw new SludiException(ErrorCodes.TOKEN_REFRESH_FAILED, e.getMessage());
        }
    }

    /**
     * Change password for authenticated user
     */
    @Transactional
    public void changePassword(String username, ChangePasswordRequestDto request) {
        log.info("Password change request for user: {}", username);

        // Find user
        OrganizationUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Verify current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            log.warn("Invalid current password for user: {}", username);
            throw new SludiException(ErrorCodes.INVALID_CURRENT_PASSWORD);
        }

        // Validate new password is different
        if (passwordEncoder.matches(request.getNewPassword(), user.getPasswordHash())) {
            throw new SludiException(ErrorCodes.NEW_PASSWORD_SAME_AS_OLD);
        }

        // Update password
        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        log.info("Password changed successfully for user: {}", username);
    }

    public List<OrganizationUserResponseDto> getAllOrgUsers() {
        List<OrganizationUser> organizationUserList = userRepository.findAll();

        return organizationUserList.stream()
                .map(this::mapToUserResponse)
                .collect(Collectors.toList());
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
                .organizationCode(user.getOrganization().getOrgCode())
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