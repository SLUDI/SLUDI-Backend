package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class BiometricDataDto {
    private byte[] fingerprint;
    private byte[] faceImage;
    private byte[] signature;
}