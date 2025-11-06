package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProofDataDto {
    private String proofType;
    private String created;
    private String creator;
    private String issuerDid;
    private String signatureValue;
}
