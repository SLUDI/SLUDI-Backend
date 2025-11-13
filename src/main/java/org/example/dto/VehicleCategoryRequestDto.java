package org.example.dto;

import lombok.Data;

import java.time.LocalDate;

@Data
public class VehicleCategoryRequestDto {
    private String category; // A, B, C
    private String description;
    private LocalDate validFrom;
    private LocalDate validUntil;
    private String restrictions; // category-specific restrictions
}
