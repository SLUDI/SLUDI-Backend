package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VCBlockChainResult {
    private String id;
    private List<String> context;
    private List<String> credentialTypes;
    private String issuer;
    private String issuanceDate;
    private String expirationDate;
    private String subjectDID;
    private String credentialSubjectHash;

    @Builder.Default
    private List<SupportingDocumentResponseDto> supportingDocuments = new ArrayList<>();

    private String status; // active, revoked, suspended, expired
    private ProofDataDto proof;

    // Blockchain metadata
    private String createdAt;
    private String updatedAt;
    private String blockchainTxId;
    private Long blockNumber;

    // Revocation fields
    private String revokedBy;
    private String revocationReason;
    private String revokedAt;
    private String revocationTxId;
    private Long revocationBlockNumber;
}
