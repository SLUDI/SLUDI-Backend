package org.example.controller;

import jakarta.validation.Valid;
import org.example.dto.*;
import org.example.exception.HttpStatusHandler;
import org.example.exception.SludiException;
import org.example.service.VerifiableCredentialService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/vc")
@CrossOrigin(origins = "*")
public class VerifiableCredentialController {

    private static final Logger LOGGER = Logger.getLogger(VerifiableCredentialController.class.getName());

    @Autowired
    private VerifiableCredentialService verifiableCredentialService;

    /**
     * Issue Identity VC
     * POST /api/vc/identity/credential
     */
    @PostMapping("/identity/credential")
    public ResponseEntity<ApiResponseDto<VCIssuedResponseDto>> createVCIdentity(
            @RequestPart("request") @Valid IssueIdentityVCRequestDto requestDto,
            @RequestPart(value = "supportingDocuments", required = false) List<MultipartFile> files) {

        LOGGER.info("Received request to issue VC for DID: " + requestDto.getDid());

        try {
            // Attach uploaded files to DTO
            if (files != null && !files.isEmpty()) {
                List<SupportingDocument> docs = new ArrayList<>();
                for (MultipartFile file : files) {
                    docs.add(SupportingDocument.builder()
                            .name(file.getOriginalFilename())
                            .type(file.getContentType())
                            .file(file)
                            .build());
                }
                requestDto.setSupportingDocuments(docs);
            }

            VCIssuedResponseDto response = verifiableCredentialService.issueIdentityVC(requestDto);

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

        LOGGER.info("Request received to fetch Identity VC with credentialId: " + credentialId);

        try {
            VerifiableCredentialDto credential = verifiableCredentialService.getVerifiableCredential(credentialId);

            LOGGER.info("Successfully retrieved VC for credentialId: " + credentialId);

            return ResponseEntity.ok(ApiResponseDto.<VerifiableCredentialDto>builder()
                    .success(true)
                    .message("Credential retrieved successfully")
                    .data(credential)
                    .timestamp(java.time.Instant.now())
                    .build());

        } catch (SludiException e) {
            LOGGER.log(Level.SEVERE,
                    String.format("Error retrieving VC with credentialId=%s ErrorCode=%s Message=%s",
                            credentialId, e.getErrorCode(), e.getMessage()),
                    e);

            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<VerifiableCredentialDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE,
                    String.format("Unexpected error retrieving VC with credentialId=%s", credentialId),
                    e);

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
