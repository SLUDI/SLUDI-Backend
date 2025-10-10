package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AppointmentAvailabilityResponseDto {
    private String date;
    private int availableSlots;
    private boolean fullyBooked;
}
