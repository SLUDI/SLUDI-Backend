package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class BiometricInfoDto {
    private byte[] data;
    private String type; // "fingerprint", "face"
}
