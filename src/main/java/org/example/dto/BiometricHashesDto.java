package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class BiometricHashesDto {
    private String fingerprintHash;
    private String faceImageHash;
}
