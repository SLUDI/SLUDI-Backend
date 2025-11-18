package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PresentationStatusDto {
    private String sessionId;
    private String status; // "PENDING", "FULFILLED", "COMPLETED", "EXPIRED"
    private boolean canProceed; // true if officer can proceed to issue license
    private Map<String, Object> sharedAttributes; // Available after fulfillment
    private LocalDateTime fulfilledAt;
    private LocalDateTime expiresAt;
}
