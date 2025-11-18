package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VPProofDto {
    private String type; // "Ed25519Signature2020"
    private String created; // ISO 8601 timestamp
    private String verificationMethod; // DID#key-1
    private String proofPurpose; // "authentication"
    private String proofValue; // Signature value
}
