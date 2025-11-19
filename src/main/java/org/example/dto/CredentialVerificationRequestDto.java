package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialVerificationRequestDto {

    private String credentialId;

    private String credentialType;

    private String subjectDid;

    private String signData;

    private String expirationDate;

    private ProofDataDto proof; // The proof to verify
}
