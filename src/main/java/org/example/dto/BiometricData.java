package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class BiometricData {
    private byte[] fingerprintData;
    private byte[] faceImageData;
}
