package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HyperledgerTransactionResult {
    private String transactionId;
    private Long blockNumber;
    private String status;
    private String message;
    private Instant timestamp;
    private String didId;
    private String credentialId;
}
