package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerifiablePresentationResponseDto {
    private String sessionId;
    private String status; // "VERIFIED", "INVALID"
    private String message;
}
