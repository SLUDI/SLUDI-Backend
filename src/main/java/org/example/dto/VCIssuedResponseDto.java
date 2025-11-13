package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

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
