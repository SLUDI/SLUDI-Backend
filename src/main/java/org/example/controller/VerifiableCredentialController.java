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

    /**
     * Issue Driving License VC
     * POST /api/vc/driving-license/credential
     */
    @PostMapping(value = "/driving-license/credential", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            security = {@SecurityRequirement(name = "bearerAuth")}
    )
    public ResponseEntity<ApiResponseDto<VCIssuedResponseDto>> createVCDrivingLicense(
            @RequestParam("did") @Valid String did,
            @RequestParam("issuingAuthority") @Valid String issuingAuthority,
            @RequestParam("restrictions") @Valid String restrictions,
            @RequestParam("endorsements") @Valid String endorsements,
            @RequestParam("validityYears") @Valid Integer validityYears,
            @RequestParam("medicalCheckDate") @Valid LocalDate medicalCheckDate,
            @RequestParam(value = "categoriesList") @Valid List<String> category,
            @RequestParam(value = "descriptionList") @Valid List<String> description,
            @RequestParam(value = "validFromList") @Valid List<String> validFrom,
            @RequestParam(value = "validUntilList") @Valid List<String> validUntil,
            @RequestParam(value = "vehicleRestrictionsList") @Valid List<String> vehicleRestrictions,
            @RequestParam(value = "supportingDocuments") @Valid List<MultipartFile> files,
            @RequestParam(value = "documentTypes") @Valid List<String> documentTypes,
            @RequestParam(value = "documentSides") @Valid List<String> documentSides) {

        try {
            String userName = getCurrentUsername();

            log.info("Received request to issue driving license VC for DID: {} by: {}", did, userName);

            IssueDrivingLicenseVCRequestDto issueVCRequestDto = IssueDrivingLicenseVCRequestDto.builder()
                    .did(did)
                    .issuingAuthority(issuingAuthority)
                    .restrictions(restrictions)
                    .endorsements(endorsements)
                    .validityYears(validityYears)
                    .medicalCheckDate(medicalCheckDate)
                    .build();
            // Vehicle Category Mapping
            List<VehicleCategoryRequestDto> vehicleCategoryRequestDtos = new ArrayList<>();
            for (int i = 0; i < category.size(); i++) {
                VehicleCategoryRequestDto dto = new VehicleCategoryRequestDto();
                dto.setCategory(category.get(i));
                dto.setDescription(description.size() > i ? description.get(i) : null);

                // Convert date strings safely
                dto.setValidFrom(validFrom.size() > i ? LocalDate.parse(validFrom.get(i)) : null);
                dto.setValidUntil(validUntil.size() > i ? LocalDate.parse(validUntil.get(i)) : null);
                dto.setRestrictions(vehicleRestrictions.size() > i ? vehicleRestrictions.get(i) : null);

                vehicleCategoryRequestDtos.add(dto);
            }
            issueVCRequestDto.setVehicleCategories(vehicleCategoryRequestDtos);

            // Attach uploaded files to DTO
            if (files != null && !files.isEmpty()) {
                List<SupportingDocumentRequestDto> docs = new ArrayList<>();
                for (int i = 0; i < files.size(); i++) {
                    MultipartFile file = files.get(i);
                    String docType = (documentTypes != null && documentTypes.size() > i)
                            ? documentTypes.get(i)
                            : "UNKNOWN";

                    String docSide = (documentSides != null && documentSides.size() > i)
                            ? documentSides.get(i)
                            : "UNKNOWN";

                    docs.add(SupportingDocumentRequestDto.builder()
                            .name(file.getOriginalFilename())
                            .type(docType) // e.g., NIC, Birth Certificate
                            .side(docSide)    // FRONT, BACK
                            .file(file)
                            .build());
                }
                issueVCRequestDto.setSupportingDocuments(docs);
            }

            VCIssuedResponseDto response = verifiableCredentialService.issueDrivingLicenseVC(issueVCRequestDto, userName);

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

    // Helper method to get current authenticated username
    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new SludiException(ErrorCodes.AUTH_FAILED);
        }
        return authentication.getName();
    }
}
