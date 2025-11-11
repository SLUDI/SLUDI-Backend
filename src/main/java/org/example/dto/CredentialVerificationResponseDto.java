package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialVerificationResponseDto {

    private Boolean isValid; // Overall validity

    private String credentialId;

    private String issuerDid;

    private String subjectDid;

    private String verifiedAt;

    private Boolean signatureValid; // Signature verification result

    private List<String> validationErrors; // Any validation errors found
}
