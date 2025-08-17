package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ProofDataDto {
    private String proofType;
    private String created;
    private String creator;
    private String signatureValue;
}
