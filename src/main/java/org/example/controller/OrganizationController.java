package org.example.controller;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

import org.example.dto.*;
import org.example.service.OrganizationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;

@RestController
@Slf4j
@RequestMapping("api/organization")
@CrossOrigin(origins = "*")
public class OrganizationController {
    @Autowired
    private OrganizationService organizationService;

    /**
     * Create new organization (Super Admin only)
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
                        .message("Organization registered successfully")
                        .data(response)
                        .timestamp(Instant.now())
                        .build());

    }

    /**
     * Update organization details (Super Admin only)
     */
    @PutMapping("/update-organization/{id}")
    public ResponseEntity<ApiResponseDto<OrganizationResponse>> updateOrganization(
            @PathVariable Long id,
            @Valid @RequestBody UpdateOrganizationRequest request){
        log.info("Updating organization: {}", request.getName());
        long superAdminId = 134344656;
        OrganizationResponse response = organizationService.updateOrganization(id, request, superAdminId);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponseDto.<OrganizationResponse>builder()
                        .success(true)
                        .message("Organization updated successfully")
                        .data(response)
                        .timestamp(Instant.now())
                        .build());
    }

    /**
     * Fetch all organizations
     */
    @GetMapping("/")
    public ResponseEntity<ApiResponseDto<List<OrganizationResponse>>> getAllOrganizations(){
        log.info("Fetching all organizations");
        List<OrganizationResponse> organizationResponses = organizationService.getAllOrganizations();
        return ResponseEntity.status(HttpStatus.FOUND)
                .body(ApiResponseDto.<List<OrganizationResponse>>builder()
                        .success(true)
                        .message("Organizations fetched successfully")
                        .data(organizationResponses)
                        .timestamp(Instant.now())
                        .build());
    }

    /**
     *  Fetch organization details by organization id
     * @param id
     */
    @GetMapping("/get-organization/{id}")
    public ResponseEntity<ApiResponseDto<OrganizationDetailResponse>> getOrganizationById(
           @PathVariable Long id){
        log.info("Fetching organization {}",id);
        OrganizationDetailResponse response = organizationService.getOrganizationDetails(id);
        return ResponseEntity.status(HttpStatus.FOUND)
                .body(ApiResponseDto.<OrganizationDetailResponse>builder()
                        .success(true)
                        .message("Organization fetched successfully")
                        .data(response)
                        .timestamp(Instant.now())
                        .build());
    }


    /**
     *  Approve a organization (Super Admin only)
     * @param id
     */
    @PutMapping("/approve/{id}")
    public ResponseEntity<ApiResponseDto<OrganizationResponse>> approveOrganization(
            @PathVariable Long id){
        log.info("Approving organization: {}", id);
        long superAdminId = 134344656;
        OrganizationResponse response = organizationService.approveOrganization(id,superAdminId);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponseDto.<OrganizationResponse>builder()
                        .success(true)
                        .message("Approved organization successfully")
                        .data(response)
                        .timestamp(Instant.now())
                        .build());
   }

    /**
     * Customize organization permissions (Super Admin only)
     */
    @PutMapping("/{id}/permissions")
    public ResponseEntity<ApiResponseDto<OrganizationDetailResponse>> customizePermissions(
            @PathVariable Long id,
            @Valid @RequestBody CustomPermissionsRequest request) {

        log.info("Customizing permissions for organization ID: {}", id);
        // TODO: Define method for get supper admin id
        long superAdminId = 134344656;
        //Long superAdminId = SecurityUtils.getCurrentUserId();
        OrganizationDetailResponse response = organizationService.customizePermissions(
                id, request, superAdminId);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponseDto.<OrganizationDetailResponse>builder()
                        .success(true)
                        .message("Permissions customized successfully")
                        .data(response)
                        .timestamp(Instant.now())
                        .build());
    }

    /**
     * Suspend organization (Super Admin only)
     */
    @PutMapping("/{id}/suspend")
    public ResponseEntity<ApiResponseDto<OrganizationResponse>> suspendOrganization(
            @PathVariable Long id,
            @Valid @RequestBody SuspendOrganizationRequest request) {

        log.info("Suspending organization ID: {}", id);

        // TODO: Define method for get supper admin id
        long superAdminId = 134344656;
        //Long superAdminId = SecurityUtils.getCurrentUserId();
        OrganizationResponse response = organizationService.suspendOrganization(
                id, request.getReason(), superAdminId);

        return ResponseEntity.status(HttpStatus.ACCEPTED)
                        .body(ApiResponseDto.<OrganizationResponse>builder()
                                .success(true)
                                .message("Organization suspended successfully")
                                .data(response)
                                .timestamp(Instant.now())
                                .build());
    }

    /**
     * Reactivate suspended organization (Super Admin only)
     */
    @PutMapping("/{id}/reactivate")
    public ResponseEntity<ApiResponseDto<OrganizationResponse>> reactivateOrganization(@PathVariable Long id) {

        log.info("Reactivating organization ID: {}", id);

        // TODO: Define method for get supper admin id
        long superAdminId = 134344656;
        //Long superAdminId = SecurityUtils.getCurrentUserId();
        OrganizationResponse response = organizationService.reactivateOrganization(id, superAdminId);

        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(ApiResponseDto.<OrganizationResponse>builder()
                        .success(true)
                        .message("Organization reactivated successfully")
                        .data(response)
                        .timestamp(Instant.now())
                        .build());
    }
}
