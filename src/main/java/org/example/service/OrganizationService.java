package org.example.service;

import org.example.dto.CreateOrganizationRequest;
import org.example.dto.CustomPermissionsRequest;
import org.example.dto.OrganizationResponse;
import org.example.dto.UpdateOrganizationRequest;

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

}
