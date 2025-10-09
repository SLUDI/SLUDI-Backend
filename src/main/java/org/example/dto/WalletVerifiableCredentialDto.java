package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WalletVerifiableCredentialDto {
    private String issuanceDate;
    private String expirationDate;
    private String subjectDID;
    private CredentialSubject credentialSubject;

    private String status; // active, revoked, suspended, expired
    private ProofDataDto proof;

    private String blockchainTxId;
    private Long blockNumber;
}
