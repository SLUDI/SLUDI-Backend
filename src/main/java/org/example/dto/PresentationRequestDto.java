package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PresentationRequestDto {
    private String sessionId;
    private String requesterId;
    private String requesterName;
    private List<String> requestedAttributes;
    private String purpose;
    private LocalDateTime expiresAt;
}
