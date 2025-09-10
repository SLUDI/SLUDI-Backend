package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class VerifiableCredentialDto {
    private String id;
    private List<String> context;
    private List<String> credentialTypes;
    private String issuer;
    private String issuanceDate;
    private String expirationDate;
    private CredentialSubject credentialSubject;
    private String status; // active, revoked, suspended, expired
    private ProofDataDto proof;
    private String createdAt;
    private String updatedAt;
}
