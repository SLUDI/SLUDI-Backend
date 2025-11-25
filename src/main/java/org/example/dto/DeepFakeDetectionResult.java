package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeepFakeDetectionResult {
    private boolean authentic; // true for real
    private double real_ratio;
    private double averageConfidence;
    private String heatmapImage;
    private String status;
    private String details;

}
