package org.example.service;

import org.example.dto.*;

import java.util.List;

public interface OrganizationService {
    /**
     * Create new organization (Super Admin only)
     * Initial status: PENDING
     */
    OrganizationResponse createOrganization (CreateOrganizationRequest request, Long superAdminId);

    OrganizationResponse updateOrganization (Long organizationId, UpdateOrganizationRequest request, Long updatedBy);

    List<OrganizationResponse> getAllOrganizations();

    OrganizationResponse getOrganizationById(Long id);

    OrganizationResponse approveOrganization(Long organizationId, Long superAdminId );

    OrganizationDetailResponse customizePermissions(Long organizationId, CustomPermissionsRequest request, Long superAdminId);

    /**
     * Get organization by ID with full details
     */
    OrganizationDetailResponse getOrganizationDetails(Long organizationId);

    OrganizationResponse suspendOrganization(
            Long organizationId,
            String reason,
            Long superAdminId);

    OrganizationResponse reactivateOrganization(Long organizationId, Long superAdminId);
}
