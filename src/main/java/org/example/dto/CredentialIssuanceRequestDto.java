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
public class CredentialIssuanceRequestDto {
    private String credentialId;
    private String subjectDID;
    private String issuerDID;
    private String credentialType;
    private String credentialSubjectHash;
    private List<SupportingDocumentResponseDto> supportingDocuments;
    private String expireDate;
    private ProofDataDto proofData;
}