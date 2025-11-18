package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.enums.CredentialsType;
import org.example.exception.ErrorCodes;
import org.example.exception.HttpStatusHandler;
import org.example.exception.SludiException;
import org.example.service.VerifiableCredentialService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/vc")
@CrossOrigin(origins = "*")
public class VerifiableCredentialController {

    private final VerifiableCredentialService verifiableCredentialService;

    public VerifiableCredentialController(VerifiableCredentialService verifiableCredentialService) {
        this.verifiableCredentialService = verifiableCredentialService;
    }

    /**
     * Issue Identity VC
     * POST /api/vc/identity/credential
     */
    @PostMapping(value = "/identity/credential", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<VCIssuedResponseDto>> createVCIdentity(
            @RequestParam("did") @Valid String did,
            @RequestParam(value = "supportingDocuments", required = false) List<MultipartFile> files,
            @RequestParam(value = "documentTypes", required = false) List<String> documentTypes) {

        log.info("Received request to issue identity VC for DID: {}", did);

        try {
            String userName = getCurrentUsername();

            IssueVCRequestDto issueVCRequestDto = IssueVCRequestDto.builder()
                    .did(did)
                    .credentialType(CredentialsType.IDENTITY.toString())
                    .build();

            // Attach uploaded files to DTO
            if (files != null && !files.isEmpty()) {
                List<SupportingDocumentRequestDto> docs = new ArrayList<>();
                for (int i = 0; i < files.size(); i++) {
                    MultipartFile file = files.get(i);
                    String docType = (documentTypes != null && documentTypes.size() > i)
                            ? documentTypes.get(i)
                            : "UNKNOWN";

                    docs.add(SupportingDocumentRequestDto.builder()
                            .name(file.getOriginalFilename())
                            .type(docType) // e.g., NIC, Birth Certificate
                            .file(file)
                            .build());
                }
                issueVCRequestDto.setSupportingDocuments(docs);
            }

            VCIssuedResponseDto response = verifiableCredentialService.issueIdentityVC(issueVCRequestDto, userName);

            ApiResponseDto<VCIssuedResponseDto> apiResponse = ApiResponseDto.<VCIssuedResponseDto>builder()
                    .success(true)
                    .message("Identity Verifiable Credential issued successfully")
                    .data(response)
                    .build();

            return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);

        } catch (SludiException e) {
            ApiResponseDto<VCIssuedResponseDto> errorResponse = ApiResponseDto.<VCIssuedResponseDto>builder()
                    .success(false)
                    .message(e.getMessage())
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);

        } catch (Exception e) {
            ApiResponseDto<VCIssuedResponseDto> errorResponse = ApiResponseDto.<VCIssuedResponseDto>builder()
                    .success(false)
                    .message("Failed to issue Identity Verifiable Credential")
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @GetMapping("/identity/credential/{credentialId}")
    public ResponseEntity<ApiResponseDto<VerifiableCredentialDto>> getVCIdentity(
            @PathVariable String credentialId) {

        log.info("Request received to fetch Identity VC with credentialId: {}", credentialId);

        try {
            String id = "credential:identity:did:sludi:" + credentialId;
            VerifiableCredentialDto credential = verifiableCredentialService.getVerifiableCredential(id);

            log.info("Successfully retrieved VC for credentialId: {}", credentialId);

            return ResponseEntity.ok(ApiResponseDto.<VerifiableCredentialDto>builder()
                    .success(true)
                    .message("Credential retrieved successfully")
                    .data(credential)
                    .timestamp(java.time.Instant.now())
                    .build());

        } catch (SludiException e) {
            log.error("Error retrieving VC with credentialId: {} ErrorCode: {} Message: {}",
                    credentialId, e.getErrorCode(), e.getMessage(), e);

            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<VerifiableCredentialDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());

        } catch (Exception e) {
            log.error("Unexpected error retrieving VC with credentialId: {}", credentialId);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<VerifiableCredentialDto>builder()
                            .success(false)
                            .message("Failed to retrieve credential")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(java.time.Instant.now())
                            .build());
        }
    }

    /**
     * Initiate Driving License Request
     * POST /api/vc/driving-license/request
     */
    @PostMapping("/driving-license/request")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<DrivingLicenseRequestResponseDto>> initiateDrivingLicenseRequest() {

        log.info("Received request to initiate driving license request");

        try {
            String userName = getCurrentUsername();
            DrivingLicenseRequestResponseDto response = verifiableCredentialService.initiateDrivingLicenseRequest(userName);

            ApiResponseDto<DrivingLicenseRequestResponseDto> apiResponse = ApiResponseDto.<DrivingLicenseRequestResponseDto>builder()
                    .success(true)
                    .message("Driving license request initiated successfully")
                    .data(response)
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException e) {
            ApiResponseDto<DrivingLicenseRequestResponseDto> errorResponse = ApiResponseDto.<DrivingLicenseRequestResponseDto>builder()
                    .success(false)
                    .message(e.getMessage())
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);

        } catch (Exception e) {
            ApiResponseDto<DrivingLicenseRequestResponseDto> errorResponse = ApiResponseDto.<DrivingLicenseRequestResponseDto>builder()
                    .success(false)
                    .message("Failed to initiate driving license request")
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Get Presentation Request (called by wallet)
     * GET /api/vc/driving-license/request/{sessionId}
     */
    @GetMapping("/driving-license/request/{sessionId}")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<PresentationRequestDto>> getPresentationRequest(
            @PathVariable String sessionId) {

        log.info("Received request to get presentation request for sessionId: {}", sessionId);

        try {
            PresentationRequestDto request = verifiableCredentialService.getPresentationRequest(sessionId);

            ApiResponseDto<PresentationRequestDto> apiResponse = ApiResponseDto.<PresentationRequestDto>builder()
                    .success(true)
                    .message("Presentation request retrieved successfully")
                    .data(request)
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException e) {
            ApiResponseDto<PresentationRequestDto> errorResponse = ApiResponseDto.<PresentationRequestDto>builder()
                    .success(false)
                    .message(e.getMessage())
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);

        } catch (Exception e) {
            ApiResponseDto<PresentationRequestDto> errorResponse = ApiResponseDto.<PresentationRequestDto>builder()
                    .success(false)
                    .message("Failed to retrieve presentation request")
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Submit Verifiable Presentation (called by wallet)
     * POST /api/vc/driving-license/presentation/{sessionId}
     */
    @PostMapping("/driving-license/presentation/{sessionId}")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<VerifiablePresentationResponseDto>> submitVerifiablePresentation(
            @PathVariable String sessionId,
            @RequestBody @Valid VerifiablePresentationDto vpDto) {

        log.info("Received verifiable presentation for sessionId: {}", sessionId);

        try {
            VerifiablePresentationResponseDto response = verifiableCredentialService.submitVerifiablePresentation(sessionId, vpDto);

            ApiResponseDto<VerifiablePresentationResponseDto> apiResponse = ApiResponseDto.<VerifiablePresentationResponseDto>builder()
                    .success(true)
                    .message("Verifiable presentation submitted successfully")
                    .data(response)
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException e) {
            ApiResponseDto<VerifiablePresentationResponseDto> errorResponse = ApiResponseDto.<VerifiablePresentationResponseDto>builder()
                    .success(false)
                    .message(e.getMessage())
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);

        } catch (Exception e) {
            ApiResponseDto<VerifiablePresentationResponseDto> errorResponse = ApiResponseDto.<VerifiablePresentationResponseDto>builder()
                    .success(false)
                    .message("Failed to submit verifiable presentation")
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Check Presentation Status (called by officer dashboard)
     * GET /api/vc/driving-license/status/{sessionId}
     */
    @GetMapping("/driving-license/status/{sessionId}")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<PresentationStatusDto>> checkPresentationStatus(
            @PathVariable String sessionId) {

        log.info("Received request to check presentation status for sessionId: {}", sessionId);

        try {
            PresentationStatusDto status = verifiableCredentialService.checkPresentationStatus(sessionId);

            ApiResponseDto<PresentationStatusDto> apiResponse = ApiResponseDto.<PresentationStatusDto>builder()
                    .success(true)
                    .message("Presentation status retrieved successfully")
                    .data(status)
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (SludiException e) {
            ApiResponseDto<PresentationStatusDto> errorResponse = ApiResponseDto.<PresentationStatusDto>builder()
                    .success(false)
                    .message(e.getMessage())
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);

        } catch (Exception e) {
            ApiResponseDto<PresentationStatusDto> errorResponse = ApiResponseDto.<PresentationStatusDto>builder()
                    .success(false)
                    .message("Failed to check presentation status")
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Issue Driving License VC
     * POST /api/vc/driving-license/credential
     */
    @PostMapping(value = "/driving-license/credential", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<VCIssuedResponseDto>> issueDrivingLicenseVC(
            @RequestParam("sessionId") @Valid String sessionId,
            @RequestParam("validityYears") @Valid int validityYears,
            @RequestParam(value = "issuingAuthority", required = false) String issuingAuthority,
            @RequestParam(value = "restrictions", required = false) List<String> restrictions,
            @RequestParam(value = "endorsements", required = false) List<String> endorsements,
            @RequestParam("vehicleCategories") @Valid List<String> vehicleCategories,
            @RequestParam(value = "categoryValidFrom", required = false) List<String> categoryValidFrom,
            @RequestParam(value = "categoryValidUntil", required = false) List<String> categoryValidUntil,
            @RequestParam(value = "categoryRestrictions", required = false) List<String> categoryRestrictions,
            @RequestParam(value = "supportingDocuments", required = false) List<MultipartFile> files,
            @RequestParam(value = "documentTypes", required = false) List<String> documentTypes) {

        log.info("Received request to issue driving license VC for sessionId: {}", sessionId);

        try {
            String userName = getCurrentUsername();

            // Build vehicle category DTOs
            List<VehicleCategoryRequestDto> vehicleCategoryDtos = new ArrayList<>();
            for (int i = 0; i < vehicleCategories.size(); i++) {
                VehicleCategoryRequestDto categoryDto = VehicleCategoryRequestDto.builder()
                        .category(vehicleCategories.get(i))
                        .validFrom(categoryValidFrom != null && categoryValidFrom.size() > i ?
                                LocalDate.parse(categoryValidFrom.get(i)) : null)
                        .validUntil(categoryValidUntil != null && categoryValidUntil.size() > i ?
                                LocalDate.parse(categoryValidUntil.get(i)) : null)
                        .restrictions(categoryRestrictions != null && categoryRestrictions.size() > i ?
                                categoryRestrictions.get(i) : null)
                        .build();
                vehicleCategoryDtos.add(categoryDto);
            }

            // Attach uploaded files to DTO
            List<SupportingDocumentRequestDto> docs = new ArrayList<>();
            if (files != null && !files.isEmpty()) {
                for (int i = 0; i < files.size(); i++) {
                    MultipartFile file = files.get(i);
                    String docType = (documentTypes != null && documentTypes.size() > i)
                            ? documentTypes.get(i)
                            : "UNKNOWN";

                    docs.add(SupportingDocumentRequestDto.builder()
                            .name(file.getOriginalFilename())
                            .type(docType) // e.g., Test Certificate, Medical Report
                            .file(file)
                            .build());
                }
            }

            IssueDrivingLicenseVCRequestDto request = IssueDrivingLicenseVCRequestDto.builder()
                    .sessionId(sessionId)
                    .validityYears(validityYears)
                    .issuingAuthority(issuingAuthority)
                    .restrictions(restrictions)
                    .endorsements(endorsements)
                    .vehicleCategories(vehicleCategoryDtos)
                    .supportingDocuments(docs)
                    .build();

            VCIssuedResponseDto response = verifiableCredentialService.issueDrivingLicenseVC(request, userName);

            ApiResponseDto<VCIssuedResponseDto> apiResponse = ApiResponseDto.<VCIssuedResponseDto>builder()
                    .success(true)
                    .message("Driving License Verifiable Credential issued successfully")
                    .data(response)
                    .build();

            return ResponseEntity.status(HttpStatus.CREATED).body(apiResponse);

        } catch (SludiException e) {
            ApiResponseDto<VCIssuedResponseDto> errorResponse = ApiResponseDto.<VCIssuedResponseDto>builder()
                    .success(false)
                    .message(e.getMessage())
                    .build();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);

        } catch (Exception e) {
            ApiResponseDto<VCIssuedResponseDto> errorResponse = ApiResponseDto.<VCIssuedResponseDto>builder()
                    .success(false)
                    .message("Failed to issue Driving License Verifiable Credential")
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Get Vehicle Category Descriptions
     * GET /api/vc/driving-license/vehicle-categories
     */
    @GetMapping("/driving-license/vehicle-categories")
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<Map<String, String>>> getVehicleCategoryDescriptions() {

        log.info("Received request to get vehicle category descriptions");

        try {
            Map<String, String> categories = verifiableCredentialService.getVehicleCategoryDescriptions();

            ApiResponseDto<Map<String, String>> apiResponse = ApiResponseDto.<Map<String, String>>builder()
                    .success(true)
                    .message("Vehicle category descriptions retrieved successfully")
                    .data(categories)
                    .build();

            return ResponseEntity.ok(apiResponse);

        } catch (Exception e) {
            ApiResponseDto<Map<String, String>> errorResponse = ApiResponseDto.<Map<String, String>>builder()
                    .success(false)
                    .message("Failed to retrieve vehicle category descriptions")
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }
    // Helper method to get current authenticated username
    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new SludiException(ErrorCodes.AUTH_FAILED);
        }
        return authentication.getName();
    }
}
