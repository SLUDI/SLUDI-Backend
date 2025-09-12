package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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

    private String subjectDid;
    private List<String> credentialType;

    private String issuerDid;
    private String issuanceDate;
    private String expirationDate;

    private String status;

    private String blockchainTxId;
    private Long blockNumber;

    private String credentialSubjectHash;
}
