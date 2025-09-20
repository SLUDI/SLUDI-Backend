package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;

@Data
@Builder
public class SelectedDatesDto {
    private LocalDate date1;
    private LocalDate date2;
    private LocalDate date3;
}
