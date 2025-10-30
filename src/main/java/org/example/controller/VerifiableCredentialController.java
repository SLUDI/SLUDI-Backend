package org.example.controller;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.exception.HttpStatusHandler;
import org.example.exception.SludiException;
import org.example.service.VerifiableCredentialService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

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
    public ResponseEntity<ApiResponseDto<VCIssuedResponseDto>> createVCIdentity(
            @RequestParam("did") @Valid String did,
            @RequestParam(value = "supportingDocuments", required = false) List<MultipartFile> files,
            @RequestParam(value = "documentTypes", required = false) List<String> documentTypes) {

        log.info("Received request to issue VC for DID: {}", did);

        try {
            String id = "did:sludi:" + did;

            IssueVCRequestDto issueVCRequestDto = IssueVCRequestDto.builder()
                    .did(id)
                    .credentialType("identity")
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

            VCIssuedResponseDto response = verifiableCredentialService.issueVC(issueVCRequestDto);

            ApiResponseDto<VCIssuedResponseDto> apiResponse = ApiResponseDto.<VCIssuedResponseDto>builder()
                    .success(true)
                    .message("Verifiable Credential issued successfully")
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
                    .message("Failed to issue Verifiable Credential")
                    .build();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @GetMapping("/identity/credential/{credentialId}")
    public ResponseEntity<ApiResponseDto<VerifiableCredentialDto>> getVCIdentity(
            @PathVariable String credentialId) {

        log.info("Request received to fetch Identity VC with credentialId: {}", credentialId);

        try {
            VerifiableCredentialDto credential = verifiableCredentialService.getVerifiableCredential(credentialId);

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

}
