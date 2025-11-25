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
public class SyncReportDto {
    private Integer totalEntities;
    private Integer syncedCount;
    private Integer pendingCount;
    private Integer failedCount;
    private List<SyncStatusDto> failedSyncs;
    private String syncDuration;
}
