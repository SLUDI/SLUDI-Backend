package org.example.sedeer;

import org.example.entity.*;
import org.example.repository.*;
import org.example.service.FabricCAService;
import org.example.service.FabricOrgAssignmentService;
import org.example.utils.FabricProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.CreatePermissionTemplateRequest;
import org.example.dto.OrganizationUserRequestDto;
import org.example.dto.OrganizationUserResponseDto;
import org.example.enums.OrganizationStatus;
import org.example.enums.OrganizationType;
import org.example.enums.PredefinedRole;
import org.example.enums.TemplateCategory;
import org.example.service.OrganizationUserService;
import org.example.service.PermissionService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.List;

@Configuration
@Slf4j
public class DataInitializer {

    @Autowired
    private FabricProperties fabricProperties;

    @Bean
    @Transactional
    public CommandLineRunner initFabricConfigs(
            FabricOrgConfigRepository fabricRepository,
            PermissionTemplateRepository templateRepository,
            OrganizationRepository organizationRepository,
            OrganizationRoleRepository roleRepository,
            OrganizationUserRepository userRepository,
            OrganizationOnboardingRepository onboardingRepository,
            FabricOrgAssignmentService fabricOrgAssignmentService,
            PermissionService permissionService,
            OrganizationUserService userService,
            FabricCAService fabricCAService
    ) {
        return args -> {
            log.info("========================================");
            log.info("Starting Data Initialization...");
            log.info("========================================");

            // Step 1: Seed Fabric Organizations
            log.info("Step 1: Initializing Fabric Organizations...");
            FabricOrgConfig org1Fabric = initializeFabricOrg1(fabricRepository);
            FabricOrgConfig org2Fabric = initializeFabricOrg2(fabricRepository);

            // Step 2: Verify Fabric CA Admin Enrollment
            log.info("Step 2: Verifying Fabric CA Admin Enrollment...");
            try {
                // Ensure admin is enrolled for Org1
                fabricCAService.getAdminUser("Org1MSP");
                log.info("✓ Org1MSP CA Admin verified");
            } catch (Exception e) {
                log.error("✗ Failed to verify Org1MSP CA Admin. Make sure admin credentials exist at crypto path.", e);
                throw new RuntimeException("CA Admin verification failed. Cannot proceed with user enrollment.", e);
            }

            // Step 3: Seed Permission Template
            log.info("Step 3: Initializing Permission Template...");
            initializePermissionTemplate(templateRepository, permissionService);

            // Step 4: Seed Citizen Registration Department
            log.info("Step 4: Initializing Citizen Registration Department...");
            Organization citizenOrg = initializeCitizenOrganization(
                    organizationRepository,
                    templateRepository,
                    fabricRepository,
                    fabricOrgAssignmentService
            );

            // Step 5: Initialize Organization Roles
            log.info("Step 5: Initializing Organization Roles...");
            initializeOrganizationRoles(roleRepository, userService, citizenOrg);

            // Step 6: Create Admin User
            log.info("Step 6: Creating Admin User...");
            createAdminUser(userRepository, roleRepository, userService, citizenOrg);

            // Step 7: Create Regular User
            log.info("Step 7: Creating Regular User...");
            createRegularUser(userRepository, roleRepository, userService, citizenOrg);

            log.info("========================================");
            log.info("Data Initialization Completed Successfully!");
            log.info("========================================");
        };
    }

    private FabricOrgConfig initializeFabricOrg1(FabricOrgConfigRepository fabricRepository) {
        if (!fabricRepository.existsByMspId("Org1MSP")) {
            String org1BasePath = fabricProperties.getBasePath() + "/org1.example.com";

            FabricOrgConfig org1 = FabricOrgConfig.builder()
                    .mspId(fabricProperties.getOrg1().getMspId())
                    .channelName(fabricProperties.getOrg1().getChannelName())
                    .chainCodeName(fabricProperties.getOrg1().getChaincodeName())
                    .cryptoPath(org1BasePath)
                    .networkPath(org1BasePath + "/connection-org1.json")
                    .peerEndpoint(fabricProperties.getOrg1().getPeerEndpoint())
                    .ordererEndpoint(fabricProperties.getOrg1().getOrdererEndpoint())
                    .caEndpoint(fabricProperties.getOrg1().getCaEndpoint())
                    .walletPath(org1BasePath + "/users")
                    .isAssigned(false)
                    .build();

            org1 = fabricRepository.save(org1);
            log.info("✓ Fabric Org1MSP configuration created");
            return org1;
        } else {
            log.info("✓ Fabric Org1MSP configuration already exists");
            return fabricRepository.findByMspId("Org1MSP");
        }
    }

    private FabricOrgConfig initializeFabricOrg2(FabricOrgConfigRepository fabricRepository) {
        if (!fabricRepository.existsByMspId("Org2MSP")) {
            String org2BasePath = fabricProperties.getBasePath() + "/org2.example.com";

            FabricOrgConfig org2 = FabricOrgConfig.builder()
                    .mspId(fabricProperties.getOrg2().getMspId())
                    .channelName(fabricProperties.getOrg2().getChannelName())
                    .chainCodeName(fabricProperties.getOrg2().getChaincodeName())
                    .cryptoPath(org2BasePath)
                    .networkPath(org2BasePath + "/connection-org2.json")
                    .peerEndpoint(fabricProperties.getOrg2().getPeerEndpoint())
                    .ordererEndpoint(fabricProperties.getOrg2().getOrdererEndpoint())
                    .caEndpoint(fabricProperties.getOrg2().getCaEndpoint())
                    .walletPath(org2BasePath + "/users")
                    .isAssigned(false)
                    .build();

            org2 = fabricRepository.save(org2);
            log.info("✓ Fabric Org2MSP configuration created");
            return org2;
        } else {
            log.info("✓ Fabric Org2MSP configuration already exists");
            return fabricRepository.findByMspId("Org2MSP");
        }
    }

    private void initializePermissionTemplate(
            PermissionTemplateRepository templateRepository,
            PermissionService permissionService) {

        if (!templateRepository.existsByTemplateCode("CITIZEN_REG_TEMPLATE")) {
            try {
                CreatePermissionTemplateRequest templateRequest = new CreatePermissionTemplateRequest();
                templateRequest.setTemplateCode("CITIZEN_REG_TEMPLATE");
                templateRequest.setName("Citizen Registration Department Permissions");
                templateRequest.setCategory(TemplateCategory.GOVERNMENT);
                templateRequest.setDescription("Base permissions for Citizen Registration Department organization");

                // Define base permissions
                List<String> basePermissions = Arrays.asList(
                        // Citizen management
                        "citizen:create",
                        "citizen:view",
                        "citizen:update",
                        "citizen:deactivate",
                        "citizen:issue_did",
                        "citizen:issue_identity_credentials",
                        "citizen:verify_identity",

                        // Identity permissions
                        "identity:read",
                        "identity:verify",
                        "identity:search",
                        "identity:history:read",
                        "identity:kyc",
                        "identity:kyc:update",
                        "identity:kyc:approve",

                        // Administrative permissions
                        "WRITE",
                        "READ",
                        "MANAGE_ROLES",
                        "MANAGE_USERS",
                        "DELETE"
                );
                templateRequest.setBasePermissions(basePermissions);

                // ADMIN role - gets all permissions
                PredefinedRole.RoleInstance adminRole = PredefinedRole.ADMIN
                        .withAllPermissions(basePermissions);

                // USER role - limited permissions
                PredefinedRole.RoleInstance userRole = PredefinedRole.USER
                        .withPermissions(Arrays.asList(
                                "citizen:create",
                                "citizen:view",
                                "citizen:update",
                                "citizen:issue_identity_credentials",
                                "citizen:verify_identity",
                                "identity:read",
                                "identity:verify",
                                "identity:search",
                                "READ",
                                "WRITE"
                        ));

                List<PredefinedRole.RoleInstance> predefinedRoles = Arrays.asList(adminRole, userRole);
                templateRequest.setPredefinedRoles(predefinedRoles);

                permissionService.addPermissionTemplate(templateRequest);
                log.info("✓ Citizen Registration Department Permission Template created");

            } catch (Exception e) {
                log.error("✗ Failed to initialize permission template", e);
                throw new RuntimeException("Failed to initialize permission template", e);
            }
        } else {
            log.info("✓ Permission template already exists");
        }
    }

    private Organization initializeCitizenOrganization(
            OrganizationRepository organizationRepository,
            PermissionTemplateRepository templateRepository,
            FabricOrgConfigRepository fabricRepository,
            FabricOrgAssignmentService fabricOrgAssignmentService) {

        if (!organizationRepository.existsByNameIgnoreCase("Citizen Registration Department")) {
            // Get permission template
            PermissionTemplate citizenTemplate = templateRepository.findByTemplateCode("CITIZEN_REG_TEMPLATE");
            if (citizenTemplate == null) {
                throw new RuntimeException("Permission template 'CITIZEN_REG_TEMPLATE' not found");
            }

            // Create organization
            Organization citizenOrg = Organization.builder()
                    .orgCode("CITIZEN_REG_DEPT")
                    .name("Citizen Registration Department")
                    .template(citizenTemplate)
                    .orgType(OrganizationType.GOVERNMENT)
                    .sector("Public Administration")
                    .contactEmail("admin@citizen.gov")
                    .contactPhone("+94 11 1234567")
                    .address("Colombo, Sri Lanka")
                    .city("Colombo")
                    .postalCode("00100")
                    .status(OrganizationStatus.ACTIVE)
                    .createdBy(null)
                    .build();

            citizenOrg = organizationRepository.save(citizenOrg);

            // Assign Fabric organization
            try {
                OrganizationOnboarding onboarding = fabricOrgAssignmentService
                        .assignFabricOrganization(citizenOrg);

                // Mark Fabric org as assigned
                FabricOrgConfig org1Fabric = fabricRepository.findByMspId(onboarding.getMspId());
                org1Fabric.setIsAssigned(true);
                fabricRepository.save(org1Fabric);

                log.info("✓ Organization 'Citizen Registration Department' created and onboarded to {}",
                        onboarding.getMspId());
            } catch (Exception e) {
                log.error("✗ Failed to onboard organization to Fabric", e);
                throw new RuntimeException("Failed to onboard organization", e);
            }

            return citizenOrg;
        } else {
            log.info("✓ Organization 'Citizen Registration Department' already exists");
            return organizationRepository.findByNameIgnoreCase("Citizen Registration Department")
                    .orElseThrow(() -> new RuntimeException("Failed to retrieve organization"));
        }
    }

    private void initializeOrganizationRoles(
            OrganizationRoleRepository roleRepository,
            OrganizationUserService userService,
            Organization organization) {

        if (!roleRepository.existsByOrganizationId(organization.getId())) {
            try {
                List<OrganizationRole> roles = userService.initializeOrganizationRoles(organization.getId());
                log.info("✓ {} roles initialized for organization", roles.size());

                // Log created roles
                roles.forEach(role ->
                        log.info("  - Role: {} (Permissions: {})", role.getRoleCode(), role.getPermissions().size())
                );
            } catch (Exception e) {
                log.error("✗ Failed to initialize organization roles", e);
                throw new RuntimeException("Failed to initialize roles", e);
            }
        } else {
            List<OrganizationRole> existingRoles = roleRepository.findByOrganizationId(organization.getId());
            log.info("✓ Organization roles already initialized ({} roles)", existingRoles.size());
        }
    }

    private void createAdminUser(
            OrganizationUserRepository userRepository,
            OrganizationRoleRepository roleRepository,
            OrganizationUserService userService,
            Organization organization) {

        if (!userRepository.existsByUsername("citizen_admin")) {
            try {
                log.info("Creating admin user 'citizen_admin'...");

                // Get ADMIN role
                OrganizationRole adminRole = roleRepository
                        .findByOrganizationIdAndRoleCode(organization.getId(), "ADMIN")
                        .orElseThrow(() -> new RuntimeException("ADMIN role not found"));

                // Create admin user request
                OrganizationUserRequestDto adminRequest = new OrganizationUserRequestDto();
                adminRequest.setOrganizationId(organization.getId());
                adminRequest.setUsername("citizen_admin");
                adminRequest.setEmail("tishanshamika200@gmail.com");
                adminRequest.setPassword("Admin@123");
                adminRequest.setFirstName("System");
                adminRequest.setLastName("Administrator");
                adminRequest.setPhone("+94 11 1234567");
                adminRequest.setDepartment("Administration");
                adminRequest.setDesignation("System Administrator");
                adminRequest.setJobTitle("IT Administrator");
                adminRequest.setRoleId(adminRole.getId());
                adminRequest.setCreatedBy(null);

                // Register user
                OrganizationUserResponseDto adminUser = userService.registerUser(adminRequest);
                log.info("  - User registered: {} (ID: {})", adminUser.getUsername(), adminUser.getUserId());

                // Auto-approve and enroll on blockchain
                log.info("  - Approving and enrolling user on blockchain...");
                OrganizationUserResponseDto approvedUser = userService.approveUser(adminUser.getUserId(), null);

                log.info("✓ Admin user created successfully");
                log.info("  - Username: {}", approvedUser.getUsername());
                log.info("  - Email: {}", approvedUser.getEmail());
                log.info("  - Fabric User ID: {}", approvedUser.getFabricUserId());
                log.info("  - Enrolled on Blockchain: {}", approvedUser.getIsEnrolledOnBlockchain());

            } catch (Exception e) {
                log.error("✗ Failed to create admin user", e);
                log.error("Error details: {}", e.getMessage());
                // Don't throw - allow initialization to continue
            }
        } else {
            log.info("✓ Admin user 'citizen_admin' already exists");
        }
    }

    private void createRegularUser(
            OrganizationUserRepository userRepository,
            OrganizationRoleRepository roleRepository,
            OrganizationUserService userService,
            Organization organization) {

        if (!userRepository.existsByUsername("citizen_user")) {
            try {
                log.info("Creating regular user 'citizen_user'...");

                // Get USER role
                OrganizationRole userRole = roleRepository
                        .findByOrganizationIdAndRoleCode(organization.getId(), "USER")
                        .orElseThrow(() -> new RuntimeException("USER role not found"));

                // Create regular user request
                OrganizationUserRequestDto userRequest = new OrganizationUserRequestDto();
                userRequest.setOrganizationId(organization.getId());
                userRequest.setUsername("citizen_user");
                userRequest.setEmail("shamikamihiran97@gmail.com");
                userRequest.setPassword("User@123");
                userRequest.setFirstName("John");
                userRequest.setLastName("Doe");
                userRequest.setPhone("+94 11 7654321");
                userRequest.setDepartment("Registration");
                userRequest.setDesignation("Registration Officer");
                userRequest.setJobTitle("Registration Officer");
                userRequest.setRoleId(userRole.getId());
                userRequest.setCreatedBy(null);

                // Register user
                OrganizationUserResponseDto regularUser = userService.registerUser(userRequest);
                log.info("  - User registered: {} (ID: {})", regularUser.getUsername(), regularUser.getUserId());

                // Auto-approve and enroll on blockchain
                log.info("  - Approving and enrolling user on blockchain...");
                OrganizationUserResponseDto approvedUser = userService.approveUser(regularUser.getUserId(), null);

                log.info("✓ Regular user created successfully");
                log.info("  - Username: {}", approvedUser.getUsername());
                log.info("  - Email: {}", approvedUser.getEmail());
                log.info("  - Fabric User ID: {}", approvedUser.getFabricUserId());
                log.info("  - Enrolled on Blockchain: {}", approvedUser.getIsEnrolledOnBlockchain());

            } catch (Exception e) {
                log.error("✗ Failed to create regular user", e);
                log.error("Error details: {}", e.getMessage());
                // Don't throw - allow initialization to continue
            }
        } else {
            log.info("✓ Regular user 'citizen_user' already exists");
        }
    }
}