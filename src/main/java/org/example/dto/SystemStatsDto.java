package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SystemStatsDto {
    private Integer totalDIDs;
    private Integer activeDIDs;
    private Integer totalCredentials;
    private Integer activeCredentials;
    private Integer revokedCredentials;
    private Long blockHeight;
    private String lastUpdated;
}
