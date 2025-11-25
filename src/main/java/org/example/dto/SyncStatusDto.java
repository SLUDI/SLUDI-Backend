package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SyncStatusDto {
    private String entityType;
    private String entityId;
    private String syncStatus;
    private LocalDateTime lastSyncedAt;
    private String blockchainTxId;
    private Long blockNumber;
    private String errorMessage;
    private Integer retryCount;
}
