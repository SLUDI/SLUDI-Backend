package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DIDCreateResponseDto {
    private UUID userId;
    private String didId;
    private String status;
    private String message;
    private String blockchainTxId;
}
