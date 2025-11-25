package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BiometricVerificationResult {
    private boolean authentic;
    private String reason;

    public static BiometricVerificationResult success() {
        return BiometricVerificationResult.builder().authentic(true).build();
    }

    public static BiometricVerificationResult failed(String reason) {
        return BiometricVerificationResult.builder().authentic(false).reason(reason).build();
    }
}