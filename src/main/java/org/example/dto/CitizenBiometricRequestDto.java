package org.example.dto;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.utils.DoubleListDeserializer;

import java.util.List;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CitizenBiometricRequestDto {
    private UUID userId;

    @JsonDeserialize(using = DoubleListDeserializer.class)
    private List<Double> faceEmbedding;

    private String fingerprintBase64;
}
