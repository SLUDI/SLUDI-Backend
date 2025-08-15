package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "credential_status")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialStatus {

    @Id
    private String credentialId;
    private String status; // active, revoked, suspended, expired
    private String statusReason;
    private LocalDateTime statusChangedAt;
    private String statusChangedBy; // DID of the entity that changed status
    private String revocationListUrl;
    private Integer revocationListIndex;
    private String blockchainTxId;
    private Long blockNumber;
}
