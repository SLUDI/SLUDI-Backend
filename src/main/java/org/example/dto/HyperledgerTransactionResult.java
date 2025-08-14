package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class HyperledgerTransactionResult {
    private String transactionId;
    private String blockNumber;
}
