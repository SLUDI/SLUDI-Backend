package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "verifiable_credentials")
public class VerifiableCredential {

    @Id
    @Column(name = "credential_id")
    private String id;

    @ElementCollection
    @CollectionTable(name = "credential_contexts", joinColumns = @JoinColumn(name = "credential_id"))
    @Column(name = "context_url")
    private List<String> context;

    @ElementCollection
    @CollectionTable(name = "credential_types", joinColumns = @JoinColumn(name = "credential_id"))
    @Column(name = "credential_type")
    private List<String> credentialTypes;

    private String issuer;
    private String issuanceDate;
    private String expirationDate;

    @Embedded
    private CredentialSubject credentialSubject;

    private String status; // active, revoked, suspended, expired

    @Embedded
    private ProofData proof;

    private String createdAt;
    private String updatedAt;
    private String blockchainTxId;
    private Long blockNumber;
    private String revokedBy;
    private String revocationReason;
    private String revokedAt;
    private String revocationTxId;
    private Long revocationBlockNumber;

    public VerifiableCredential(List<String> context, String id, List<String> credentialTypes,
                                String issuer, String issuanceDate, String expirationDate,
                                CredentialSubject credentialSubject, String status, ProofData proof, String createdAt,
                                String updatedAt, String blockchainTxId, Long blockNumber) {
        this.context = context;
        this.id = id;
        this.credentialTypes = credentialTypes;
        this.issuer = issuer;
        this.issuanceDate = issuanceDate;
        this.expirationDate = expirationDate;
        this.credentialSubject = credentialSubject;
        this.status = status;
        this.proof = proof;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.blockchainTxId = blockchainTxId;
        this.blockNumber = blockNumber;
    }
}
