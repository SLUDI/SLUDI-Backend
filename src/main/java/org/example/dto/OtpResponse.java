package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
public class OtpResponse {
    private String message;
    private LocalDateTime timestamp;
}