package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VCIssuedResponseDto {
    private String credentialId;
    private String subjectDID;
    private String credentialType;
    private String status;
    private String message;
    private String blockchainTxId;
}
