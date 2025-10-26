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
     * Update organization details
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

    @GetMapping("/get-organization/{id}")
    public ResponseEntity<ApiResponseDto<OrganizationResponse>> getOrganizationById(
           @PathVariable Long id){
        log.info("Fetching organization {}",id);
        OrganizationResponse response = organizationService.getOrganizationById(id);
        return ResponseEntity.status(HttpStatus.FOUND)
                .body(ApiResponseDto.<OrganizationResponse>builder()
                        .success(true)
                        .message("Organization fetched successfully")
                        .data(response)
                        .timestamp(Instant.now())
                        .build());
    }
}
