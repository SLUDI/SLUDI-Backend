package org.example.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.CreateOrganizationRequest;
import org.example.dto.CustomPermissionsRequest;
import org.example.dto.OrganizationResponse;
import org.example.dto.UpdateOrganizationRequest;
import org.example.entity.Organization;
import org.example.entity.PermissionTemplate;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.OrganizationRepository;
import org.example.util.OrgCodeGenerator;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
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
}
