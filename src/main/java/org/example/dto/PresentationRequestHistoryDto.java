package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PresentationRequestHistoryDto {
    private UUID id;

    private String sessionId;

    private String requesterId;
    private String requesterName;

    private List<String> requestedAttributes;

    private String purpose;

    private String status;

    private LocalDateTime createdAt;

    private LocalDateTime expiresAt;

    private LocalDateTime fulfilledAt;

    private LocalDateTime completedAt;

    private Map<String, Object> sharedAttributes;

    private String issuedCredentialId;

    private String errorMessage;
}
