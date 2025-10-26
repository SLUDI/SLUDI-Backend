package org.example.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.CreateOrganizationRequest;
import org.example.dto.OrganizationResponse;
import org.example.entity.Organization;
import org.example.entity.PermissionTemplate;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.OrganizationRepository;
import org.example.util.OrgCodeGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.logging.Logger;

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
//        while (organizationRepository.existsByOrgCode(orgCode)){
//
//            orgCode = OrgCodeGenerator.generateWithSuffix(request.getName(), request.getOrganizationType()); // Need this method to create new orgCode instead of putting exception
//        }
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
