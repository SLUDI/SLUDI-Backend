package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "verifiable_credentials")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerifiableCredential {

    @Id
    private String id;

    @ElementCollection
    @CollectionTable(name = "credential_contexts", joinColumns = @JoinColumn(name = "credential_id"))
    @Column(name = "context_url")
    private List<String> context;

    @ElementCollection
    @CollectionTable(name = "credential_types", joinColumns = @JoinColumn(name = "credential_id"))
    @Column(name = "credential_type")
    private List<String> type;

    private String issuer;
    private String issuanceDate;
    private String expirationDate;

    @Embedded
    private CredentialSubject credentialSubject;

    private String status; // active, revoked, suspended, expired

    @Embedded
    private ProofData proof;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String blockchainTxId;
    private Long blockNumber;
    private String revocationReason;
    private LocalDateTime revokedAt;

    public VerifiableCredential(List<String> context, String id, List<String> type,
                                String issuer, String issuanceDate, String expirationDate,
                                CredentialSubject credentialSubject, String status, ProofData proof) {
        this.context = context;
        this.id = id;
        this.type = type;
        this.issuer = issuer;
        this.issuanceDate = issuanceDate;
        this.expirationDate = expirationDate;
        this.credentialSubject = credentialSubject;
        this.status = status;
        this.proof = proof;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }
}
