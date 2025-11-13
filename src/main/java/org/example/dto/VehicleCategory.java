package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;

@Data
@Builder
public class VehicleCategory {
    private String category; // A, A1, B1, B, C1, C, D1, D, G1, G, J
    private String description;
    private String validFrom;
    private String validUntil;
    private String restrictions; // category-specific restrictions
}