package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
public class VCBlockChainResult {
    private String id;
    private String subjectDID;
    private List<String> context;
    private List<String> credentialTypes;
    private String issuer;
    private String issuanceDate;
    private String expirationDate;
    private String credentialSubjectHash;
    private List<SupportingDocumentDto> supportingDocuments = new ArrayList<>();
    private String status; // active, revoked, suspended, expired
    private ProofDataDto proof;
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
