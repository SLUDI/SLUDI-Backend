package org.example.dto;

import lombok.*;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@RequiredArgsConstructor
@Builder
public class FaceVerificationResultDto {
    private boolean isMatch;
    private double similarity;
    private String message;
    private LocalDateTime timestamp;
    private String citizenId;
    private boolean deepfakeDetected;
}
