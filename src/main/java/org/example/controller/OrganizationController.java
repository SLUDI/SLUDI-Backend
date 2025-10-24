package org.example.controller;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.security.SecurityUtil;
import org.example.dto.*;
import org.example.service.OrganizationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
@Slf4j
@RequestMapping("api/organization")
@CrossOrigin(origins = "*")
public class OrganizationController {
    @Autowired
    private OrganizationService organizationService;

    /**
     * Create new organization (Super Admin only)
     * POST /api/v1/organizations
     */
    @PostMapping("/create-organization")
    public ResponseEntity<ApiResponseDto<OrganizationResponse>> createOrganization(
            @Valid @RequestBody CreateOrganizationRequest request ){
        log.info("Creating organization: {}", request.getName());

        // Long superAdminId = SecurityUtil.getCurrentUserId();
        long superAdminId = 134344656; // This is for development purpose
        OrganizationResponse response = organizationService.createOrganization(request, superAdminId);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponseDto.<OrganizationResponse>builder()
                        .success(true)
                        .message("Organization registred successfully")
                        .data(response)
                        .timestamp(Instant.now())
                        .build());

    }
}
