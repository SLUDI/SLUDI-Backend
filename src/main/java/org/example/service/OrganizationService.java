package org.example.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.entity.Organization;
import org.example.entity.OrganizationOnboarding;
import org.example.entity.OrganizationUser;
import org.example.entity.PermissionTemplate;
import org.example.enums.OrganizationStatus;
import org.example.enums.TemplateCategory;
import org.example.enums.UserStatus;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.OrganizationRepository;
import org.example.repository.OrganizationUserRepository;
import org.example.utils.OrgCodeGenerator;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class OrganizationService{

    private final OrganizationRepository organizationRepository;
    private final OrganizationUserRepository userRepository;
    private final PermissionTemplateService permissionTemplateService;
    private final FabricOrgAssignmentService fabricOrgAssignmentService;
    private final OrganizationUserService userService;

    /*
    * Create new organization (Admin only)
    * */
    public OrganizationResponse createOrganization (CreateOrganizationRequest request, String userName){
        log.info("Creating new organization: {} by super admin: {}",request.getName(), userName);

        // Find user
        OrganizationUser user = userRepository.findByUsername(userName)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to create organizations
        if (!userService.verifyUserPermission(userName, "organization:create")) {
            log.warn("User {} attempted to create organization without permission", userName);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to create organization", userName);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

        // Validate template exists
        PermissionTemplate template = permissionTemplateService.getTemplateById(request.getTemplateId());

        // Check for duplicates
        if (request.getRegistrationNumber() != null &&
        organizationRepository.existsByRegistrationNumber(request.getRegistrationNumber())) {
            throw new SludiException(ErrorCodes.DUPLICATE_ORGANIZATION, request.getRegistrationNumber());
        }

        // Generate unique org code
        String orgCode = OrgCodeGenerator.generate(request.getName(), request.getOrganizationType());
        if(organizationRepository.existsByOrgCode(orgCode)){
            throw new RuntimeException("Org code already used");
        }

        //Build organization entity
        Organization organization = Organization.builder()
                .orgCode(orgCode)
                .name(request.getName())
                .template(template)
                .registrationNumber(request.getRegistrationNumber())
                .orgType(request.getOrganizationType())
                .sector(request.getSector())
                .contactEmail(request.getContactEmail())
                .contactPhone(request.getContactPhone())
                .address(request.getAddress())
                .city(request.getCity())
                .postalCode(request.getPostalCode())
                .status(OrganizationStatus.PENDING)
                .createdBy(userName)
                .build();

        // Save to database
        organization = organizationRepository.save(organization);

        // Log audit trail

        log.info("Organization created successfully with ID: {} and code: {}",
                organization.getId(), organization.getOrgCode());

        return  toOrganizationResponse(organization);
    }

    public OrganizationResponse updateOrganization (Long organizationId, UpdateOrganizationRequest request, String userName){
        log.info("Updating organization ID: {}",organizationId);

        // Find user
        OrganizationUser user = userRepository.findByUsername(userName)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to create organizations
        if (!userService.verifyUserPermission(userName, "organization:update")) {
            log.warn("User {} attempted to update organization without permission", userName);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to update organization", userName);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

        Organization organization = getOrganizationEntity(organizationId);

        if(request.getName() != null){
            organization.setName(request.getName());
        }
        if (request.getContactEmail() != null) {
            organization.setContactEmail(request.getContactEmail());
        }
        if (request.getContactPhone() != null) {
            organization.setContactPhone(request.getContactPhone());
        }
        if (request.getAddress() != null) {
            organization.setAddress(request.getAddress());
        }
        if (request.getCity() != null) {
            organization.setCity(request.getCity());
        }
        if (request.getPostalCode() != null) {
            organization.setPostalCode(request.getPostalCode());
        }

        organization = organizationRepository.save(organization);

        return toOrganizationResponse(organization);
    }

    public List<OrganizationResponse> getAllOrganizations(String userName){
        // Find user
        OrganizationUser user = userRepository.findByUsername(userName)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to create organizations
        if (!userService.verifyUserPermission(userName, "organization:view")) {
            log.warn("User {} attempted to view organizations without permission", userName);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to view organizations", userName);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

        List<Organization> organizations = organizationRepository.findAll();
        return organizations.stream()
                .map(this::toOrganizationResponse)
                .collect(Collectors.toList());
    }

    public OrganizationResponse getOrganizationById(Long id, String userName){
        // Find user
        OrganizationUser user = userRepository.findByUsername(userName)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to create organizations
        if (!userService.verifyUserPermission(userName, "organization:view")) {
            log.warn("User {} attempted to view organization without permission", userName);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to view organization", userName);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

        return toOrganizationResponse(getOrganizationEntity(id));
    }

    public OrganizationDetailResponse getOrganizationDetails(Long organizationId, String userName) {
        // Find user
        OrganizationUser user = userRepository.findByUsername(userName)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to create organizations
        if (!userService.verifyUserPermission(userName, "organization:view")) {
            log.warn("User {} attempted to view organization without permission", userName);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to view organization", userName);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

        Organization organization = organizationRepository.findByIdWithTemplate(organizationId)
                .orElseThrow(() -> new SludiException(ErrorCodes.ORGANIZATION_NOT_FOUND, String.valueOf(organizationId))
                  );

        return toOrganizationDetailResponse(organization);
    }

    public OrganizationResponse approveOrganization(Long organizationId, String userName){
        log.info("Approving organization ID: {} by super admin: {}", organizationId, userName);

        // Find user
        OrganizationUser user = userRepository.findByUsername(userName)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to create organizations
        if (!userService.verifyUserPermission(userName, "organization:approve")) {
            log.warn("User {} attempted to approve organization without permission", userName);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to approve organization", userName);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

        Organization organization = getOrganizationEntity(organizationId);

        // Validate current status
        if(organization.getStatus() != OrganizationStatus.PENDING){
            throw new SludiException(ErrorCodes.INVALID_STATUS_OPERATION, organization.getOrgCode());
        }

        // Update status
        organization.setStatus(OrganizationStatus.ACTIVE);
        organization.setApprovedBy(userName);
        organization.setApprovedAt(LocalDateTime.now());

        // Assign Fabric organization
        OrganizationOnboarding onboarding = fabricOrgAssignmentService
                .assignFabricOrganization(organization);

        organization = organizationRepository.save(organization);

        log.info("Organization approved successfully: {}", organization.getOrgCode());

        return toOrganizationResponse(organization);
    }

    public OrganizationDetailResponse customizePermissions(
            Long organizationId,
            CustomPermissionsRequest request,
            String userName) {

        log.info("Customizing permissions for organization ID: {}", organizationId);

        // Find user
        OrganizationUser user = userRepository.findByUsername(userName)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to create organizations
        if (!userService.verifyUserPermission(userName, "organization:update")) {
            log.warn("User {} attempted to update organization permission without permission", userName);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to update organization permission", userName);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

        Organization organization = getOrganizationEntity(organizationId);

        // Validate permission request
        permissionTemplateService.validateCustomPermissionsRequest(request, organization);

        // Get or create custom permissions object
        Organization.CustomPermissions customPermissions = organization.getCustomPermissions();
        if (customPermissions == null) {
            customPermissions = new Organization.CustomPermissions();
        }

        // Update added permissions
        if (request.getAdded() != null) {
            List<String> added = customPermissions.getAdded();
            if (added == null) {
                added = new ArrayList<>();
            }
            added.addAll(request.getAdded());
            customPermissions.setAdded(added);
        }

        // Update removed permissions
        if (request.getRemoved() != null) {
            List<String> removed = customPermissions.getRemoved();
            if (removed == null) {
                removed = new ArrayList<>();
            }
            removed.addAll(request.getRemoved());
            customPermissions.setRemoved(removed);
        }

        organization.setCustomPermissions(customPermissions);
        organization = organizationRepository.save(organization);

        return toOrganizationDetailResponse(organization);
    }

    /**
     * Suspend organization
     */
    public OrganizationResponse suspendOrganization(
            Long organizationId,
            String reason,
            String userName) {

        log.info("Suspending organization ID: {} by super admin: {}", organizationId, userName);

        // Find user
        OrganizationUser user = userRepository.findByUsername(userName)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to create organizations
        if (!userService.verifyUserPermission(userName, "organization:suspend")) {
            log.warn("User {} attempted to suspend organization without permission", userName);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to suspend organization", userName);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

        Organization organization = getOrganizationEntity(organizationId);

        if (organization.getStatus() != OrganizationStatus.ACTIVE) {
            throw new SludiException( ErrorCodes.ORGANIZATION_STATUS_ERROR, organization.getStatus().toString()  );
        }

        organization.setStatus(OrganizationStatus.SUSPENDED);
        organization.setSuspendedBy(userName);
        organization.setSuspendedAt(LocalDateTime.now());
        organization.setSuspensionReason(reason);

        organization = organizationRepository.save(organization);

        return toOrganizationResponse(organization);
    }

    /**
     * Reactivate suspended organization
     */
    public OrganizationResponse reactivateOrganization(Long organizationId, String userName) {
        log.info("Reactivating organization ID: {}", organizationId);

        // Find user
        OrganizationUser user = userRepository.findByUsername(userName)
                .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

        // Check if user has permission to create organizations
        if (!userService.verifyUserPermission(userName, "organization:reactive")) {
            log.warn("User {} attempted to reactive organization without permission", userName);
            throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
        }

        // Verify user is active
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("Inactive user {} attempted to reactive organization", userName);
            throw new SludiException(ErrorCodes.USER_INACTIVE);
        }

        Organization organization = getOrganizationEntity(organizationId);

        if (organization.getStatus() != OrganizationStatus.SUSPENDED) {
            throw new SludiException( ErrorCodes.ORGANIZATION_STATUS_ERROR, organization.getStatus().toString()  );
        }

        organization.setStatus(OrganizationStatus.ACTIVE);
        organization.setSuspendedBy(null);
        organization.setSuspendedAt(null);
        organization.setSuspensionReason(null);

        organization = organizationRepository.save(organization);

        return toOrganizationResponse(organization);
    }

    // Helper Methods

    private Organization getOrganizationEntity(Long organizationId) {
        return organizationRepository.findById(organizationId)
                .orElseThrow(()-> new SludiException(ErrorCodes.ORGANIZATION_NOT_FOUND, String.valueOf(organizationId)));
    }

    private OrganizationResponse toOrganizationResponse(Organization org) {
        return OrganizationResponse.builder()
                .id(org.getId())
                .orgCode(org.getOrgCode())
                .name(org.getName())
                .registrationNumber(org.getRegistrationNumber())
                .orgType(org.getOrgType())
                .sector(org.getSector())
                .contactEmail(org.getContactEmail())
                .contactPhone(org.getContactPhone())
                .address(org.getAddress())
                .city(org.getCity())
                .postalCode(org.getPostalCode())
                .status(org.getStatus())
                .templateName(org.getTemplate().getName() != null ? org.getTemplate().getName() : null)
                .templateId(org.getTemplate().getId() != null ? org.getTemplate().getId() : null )
                .createdAt(org.getCreatedAt())
                .approvedAt(org.getApprovedAt())
                .build();
    }

    private OrganizationDetailResponse toOrganizationDetailResponse(Organization org) {
        Set<String> effectivePermissions = permissionTemplateService.calculateEffectivePermissions(org);

        CustomPermissionsResponse customPerms = null;
        if (org.getCustomPermissions() != null) {
            customPerms = CustomPermissionsResponse.builder()
                    .added(org.getCustomPermissions().getAdded())
                    .removed(org.getCustomPermissions().getRemoved())
                    .build();
        }

        PermissionTemplateResponse templateResponse = null;
        if (org.getTemplate() != null) {
            templateResponse = PermissionTemplateResponse.builder()
                    .id(org.getTemplate().getId())
                    .templateCode(org.getTemplate().getTemplateCode())
                    .name(org.getTemplate().getName())
                    .category(TemplateCategory.valueOf(org.getTemplate().getCategory().name()))
                    .description(org.getTemplate().getDescription())
                    .basePermissions(org.getTemplate().getBasePermissions())
                    .build();
        }

        return OrganizationDetailResponse.builder()
                .id(org.getId())
                .orgCode(org.getOrgCode())
                .name(org.getName())
                .registrationNumber(org.getRegistrationNumber())
                .orgType(org.getOrgType())
                .sector(org.getSector())
                .contactEmail(org.getContactEmail())
                .contactPhone(org.getContactPhone())
                .address(org.getAddress())
                .city(org.getCity())
                .postalCode(org.getPostalCode())
                .template(templateResponse)
                .effectivePermissions(new ArrayList<>(effectivePermissions))
                .customPermissions(customPerms)
                .status(org.getStatus())
                .blockchainTxId(org.getBlockchainTxId())
                .blockchainBlockNumber(org.getBlockchainBlockNumber())
                .blockchainTimestamp(org.getBlockchainTimestamp())
                .createdBy(org.getCreatedBy())
                .createdAt(org.getCreatedAt())
                .approvedBy(org.getApprovedBy())
                .approvedAt(org.getApprovedAt())
                .suspendedBy(org.getSuspendedBy())
                .suspendedAt(org.getSuspendedAt())
                .suspensionReason(org.getSuspensionReason())
                .updatedAt(org.getUpdatedAt())
                .build();
    }
}
