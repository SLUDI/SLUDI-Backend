package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AIDetectionResult {
    private boolean authentic;
    private double confidence;
    private String details;
}
