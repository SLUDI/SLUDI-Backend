package org.example.dto;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.Data;
import org.example.utils.DoubleListDeserializer;

import java.util.List;
import java.util.UUID;

@Data
public class CitizenBiometricRequestDto {
    private UUID userId;

    @JsonDeserialize(using = DoubleListDeserializer.class)
    private List<Double> faceEmbedding;

    private String fingerprintBase64;
}
