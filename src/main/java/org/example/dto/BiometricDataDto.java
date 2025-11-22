package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class BiometricDataDto {
    private List<Float> faceEmbedding;
    private String fingerprintBase64;
}