package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DrivingLicenseRequestResponseDto {
    private String sessionId;
    private String requestUrl;
    private String qrCode; // Base64 encoded QR code image
    private LocalDateTime expiresAt;
    private String message;
}
