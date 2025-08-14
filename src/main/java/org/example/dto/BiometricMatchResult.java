package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class BiometricMatchResult {
    private boolean match;
    private double confidenceScore;
    private String details;
}
