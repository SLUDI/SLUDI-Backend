package org.example.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.entity.Organization;
import org.example.entity.PermissionTemplate;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.OrganizationRepository;
import org.example.util.OrgCodeGenerator;
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
public class OrganizationServiceImpl implements OrganizationService{

    private final PermissionService permissionService;

    private final OrganizationRepository organizationRepository;
    /*
    * Create new organization (Super Admin only)
    * Initial status: PENDING
    * */
    @Override
    public OrganizationResponse createOrganization (CreateOrganizationRequest request, Long superAdminId){
        log.info("Creating new organization: {} by super admin: {}",request.getName(),superAdminId);

        // Validate template exists
        PermissionTemplate template = permissionService.getTemplateById(request.getTemplateId());

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

        // TODO: Improve organization code generation step for overlapping codes
//        while (organizationRepository.existsByOrgCode(orgCode)){
//
//            orgCode = OrgCodeGenerator.generateWithSuffix(request.getName(), request.getOrganizationType()); // Need this method to create new orgCode instead of putting exception
//        }

        // TODO: Record on blockchain
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
                .status(Organization.OrganizationStatus.PENDING)
                .createdBy(superAdminId)
                .build();

        // Save to database
        organization = organizationRepository.save(organization);

        // Log audit trail

        log.info("Organization created successfully with ID: {} and code: {}",
                organization.getId(), organization.getOrgCode());

        return  toOrganizationResponse(organization);
    }

    @Override
    public OrganizationResponse updateOrganization (Long organizationId, UpdateOrganizationRequest request, Long updatedBy){
        log.info("Updating organization ID: {}",organizationId);

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

    @Override
    public List<OrganizationResponse> getAllOrganizations(){
        List<Organization> organizations = organizationRepository.findAll();
        return organizations.stream()
                .map(this::toOrganizationResponse)
                .collect(Collectors.toList());
    }

    @Override
    public OrganizationResponse getOrganizationById(Long id){
        return toOrganizationResponse(getOrganizationEntity(id));
    }

    @Override
    public OrganizationDetailResponse getOrganizationDetails(Long organizationId) {
        Organization organization = organizationRepository.findByIdWithTemplate(organizationId)
                .orElseThrow(() -> new SludiException(ErrorCodes.ORGANIZATION_NOT_FOUND, String.valueOf(organizationId))
                  );

        return toOrganizationDetailResponse(organization);
    }


    @Override
    public OrganizationResponse approveOrganization(Long organizationId, Long superAdminId){
        log.info("Approving organization ID: {} by super admin: {}", organizationId, superAdminId);
        Organization organization = getOrganizationEntity(organizationId);

        // Validate current status
        if(organization.getStatus() != Organization.OrganizationStatus.PENDING){
            throw new SludiException(ErrorCodes.INVALID_STATUS_OPERATION, organization.getOrgCode());
        }

        // Update status
        organization.setStatus(Organization.OrganizationStatus.ACTIVE);
        organization.setApprovedBy(superAdminId);
        organization.setApprovedAt(LocalDateTime.now());

        // TODO: Record on blockchain
        // String txId = fabricGatewayService.registerOrganization(organization);
        // organization.setBlockchainTxId(txId);
        // organization.setBlockchainTimestamp(LocalDateTime.now());

        organization = organizationRepository.save(organization);

        log.info("Organization approved successfully: {}", organization.getOrgCode());

        return toOrganizationResponse(organization);
    }

    @Override
    public OrganizationDetailResponse customizePermissions(
            Long organizationId,
            CustomPermissionsRequest request,
            Long superAdminId) {

        log.info("Customizing permissions for organization ID: {}", organizationId);

        Organization organization = getOrganizationEntity(organizationId);

        // Validate permission request
        permissionService.validateCustomPermissionsRequest(request, organization);

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

        // TODO: Record permission change on blockchain
        // fabricGatewayService.recordPermissionChange(organization, request);

        // Log audit trail
        //auditService.logPermissionCustomization(organization, request, superAdminId);

        return toOrganizationDetailResponse(organization);
    }

    /**
     * Suspend organization (Super Admin only)
     */
    @Override
    public OrganizationResponse suspendOrganization(
            Long organizationId,
            String reason,
            Long superAdminId) {

        log.info("Suspending organization ID: {} by super admin: {}", organizationId, superAdminId);

        Organization organization = getOrganizationEntity(organizationId);

        if (organization.getStatus() != Organization.OrganizationStatus.ACTIVE) {
            throw new SludiException( ErrorCodes.ORGANIZATION_STATUS_ERROR, organization.getStatus().toString()  );
        }

        organization.setStatus(Organization.OrganizationStatus.SUSPENDED);
        organization.setSuspendedBy(superAdminId);
        organization.setSuspendedAt(LocalDateTime.now());
        organization.setSuspensionReason(reason);

        organization = organizationRepository.save(organization);

        //  TODO : Log audit trail
        //  auditService.logOrganizationSuspension(organization, superAdminId, reason);

        return toOrganizationResponse(organization);
    }

    /**
     * Reactivate suspended organization
     */
    @Override
    public OrganizationResponse reactivateOrganization(Long organizationId, Long superAdminId) {
        log.info("Reactivating organization ID: {}", organizationId);

        Organization organization = getOrganizationEntity(organizationId);

        if (organization.getStatus() != Organization.OrganizationStatus.SUSPENDED) {
            throw new SludiException( ErrorCodes.ORGANIZATION_STATUS_ERROR, organization.getStatus().toString()  );
        }

        organization.setStatus(Organization.OrganizationStatus.ACTIVE);
        organization.setSuspendedBy(null);
        organization.setSuspendedAt(null);
        organization.setSuspensionReason(null);

        organization = organizationRepository.save(organization);

        // TODO: Log audit trail
        //auditService.logOrganizationReactivation(organization, superAdminId);

        return toOrganizationResponse(organization);
    }

    // ==================== Helper Methods ====================

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
        Set<String> effectivePermissions = permissionService.calculateEffectivePermissions(org);

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
                    .category(PermissionTemplate.TemplateCategory.valueOf(org.getTemplate().getCategory().name()))
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
