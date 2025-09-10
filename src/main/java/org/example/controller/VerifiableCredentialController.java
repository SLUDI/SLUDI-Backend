package org.example.controller;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.example.dto.ApiResponseDto;
import org.example.dto.VerifiableCredentialDto;
import org.example.exception.HttpStatusHandler;
import org.example.exception.SludiException;
import org.example.service.VerifiableCredentialService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/vc")
@CrossOrigin(origins = "*")
@Tag(name = "Verifiable Credentials", description = "Operations related to Verifiable Credentials")
public class VerifiableCredentialController {

    @Autowired
    private VerifiableCredentialService verifiableCredentialService;

    /**
     * Issue Identity VC
     * POST /api/vc/identity
     */
    @PostMapping

    /**
     * Get user Verifiable Credential by Credential ID
     * GET /api/vc/credential/{credentialId}
     */
    @GetMapping("/credential/{credentialId}")
    public ResponseEntity<ApiResponseDto<VerifiableCredentialDto>> getUserCredential(
            @PathVariable String credentialId) {
        try {
            VerifiableCredentialDto credential = verifiableCredentialService.getVerifiableCredential(credentialId);
            return ResponseEntity.ok(ApiResponseDto.<VerifiableCredentialDto>builder()
                    .success(true)
                    .message("Credential retrieved successfully")
                    .data(credential)
                    .timestamp(java.time.Instant.now())
                    .build());
        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<VerifiableCredentialDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());
        } catch (Exception e) {
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
