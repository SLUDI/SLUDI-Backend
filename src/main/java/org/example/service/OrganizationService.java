package org.example.service;

import org.example.dto.*;

import java.util.List;

public interface OrganizationService {
    /**
     * Create new organization (Super Admin only)
     * Initial status: PENDING
     */
    OrganizationResponse createOrganization (CreateOrganizationRequest request, String userName);

    OrganizationResponse updateOrganization (Long organizationId, UpdateOrganizationRequest request, String userName);

    List<OrganizationResponse> getAllOrganizations(String userName);

    OrganizationResponse getOrganizationById(Long id, String userName);

    OrganizationResponse approveOrganization(Long organizationId, String userName );

    OrganizationDetailResponse customizePermissions(Long organizationId, CustomPermissionsRequest request, String userName);

    /**
     * Get organization by ID with full details
     */
    OrganizationDetailResponse getOrganizationDetails(Long organizationId, String userName);

    OrganizationResponse suspendOrganization(
            Long organizationId,
            String reason,
            String userName);

    OrganizationResponse reactivateOrganization(Long organizationId, String userName);
}
