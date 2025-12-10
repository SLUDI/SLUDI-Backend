package org.example.dto;

import lombok.*;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class FaceVerificationResultDto {
    private boolean isMatch;
    private double similarity;
    private String message;
    private LocalDateTime timestamp;
    private String citizenId;
    private boolean deepfakeDetected;

    // Additional fields from API
    private boolean success;
    private String result;
    private Double confidence;
    private Boolean livenessCheckPassed;
    private Integer blinksDetected;
    private Double processingTimeMs;
    private Double thresholdUsed;
}
