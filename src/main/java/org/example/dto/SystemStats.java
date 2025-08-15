package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SystemStats {
    private int totalDIDs;
    private int activeDIDs;
    private int totalCredentials;
    private int activeCredentials;
    private int revokedCredentials;
    private String timestamp;
}
