package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TransactionRecodeDto {
    private String transactionId;
    private Long blockNumber;
    private String timestamp;
}
