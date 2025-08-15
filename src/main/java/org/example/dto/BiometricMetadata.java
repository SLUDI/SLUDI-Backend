package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BiometricMetadata {
    private String userId;
    private String biometricType;
    private long timestamp;
    private int originalSize;
    private boolean encrypted;
}