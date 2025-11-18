package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VehicleCategoryRequestDto {
    private String category; // A, B, C
    private String description;
    private LocalDate validFrom;
    private LocalDate validUntil;
    private String restrictions; // category-specific restrictions
}
