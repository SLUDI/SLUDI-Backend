package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class VCIssuedResponseDto {

    private String credentialId;
    private String subjectDID;
    private String credentialType;
    private String status;
    private String message;
    private String blockchainTxId;
}
