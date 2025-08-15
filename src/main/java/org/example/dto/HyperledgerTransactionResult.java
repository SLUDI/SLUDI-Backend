package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class HyperledgerTransactionResult {
    private String transactionId;
    private Long blockNumber;
    private String status;
    private String message;
    private Instant timestamp;
    private String didId;
    private String credentialId;
}
