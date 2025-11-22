package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DrivingLicenseStatsResponse {
    private Integer totalDrivingLicense;
    private Integer activeDrivingLicense;
    private Integer deactivateDrivingLicense;
    private Integer expireSoon;
}
