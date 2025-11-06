package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.util.UUID;

@Data
@Builder
public class DIDCreateResponseDto {
    private UUID userId;
    private String didId;
    private String status;
    private String message;
    private String blockchainTxId;
}
