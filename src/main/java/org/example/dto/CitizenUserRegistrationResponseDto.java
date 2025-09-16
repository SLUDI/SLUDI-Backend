package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.util.UUID;

@Data
@Builder
public class CitizenUserRegistrationResponseDto {
    private UUID userId;
    private String status;
    private String message;
}