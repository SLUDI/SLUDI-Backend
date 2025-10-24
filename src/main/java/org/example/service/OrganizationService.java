package org.example.service;

import org.example.dto.CreateOrganizationRequest;
import org.example.dto.OrganizationResponse;

public interface OrganizationService {
    /**
     * Create new organization (Super Admin only)
     * Initial status: PENDING
     */
    OrganizationResponse createOrganization (CreateOrganizationRequest request, Long superAdminId);

}
