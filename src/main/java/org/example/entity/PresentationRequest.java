package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "presentation_requests")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PresentationRequest {

    @Id
    @GeneratedValue
    @Column(columnDefinition = "uuid", updatable = false)
    private UUID id;

    @Column(unique = true, nullable = false)
    private String sessionId;

    @Column(nullable = false)
    private String requesterId; // Department

    @Column(nullable = false)
    private String requesterName;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb", nullable = false)
    private List<String> requestedAttributes;

    @Column(nullable = false)
    private String purpose;

    @Column(nullable = false)
    private String status; // PENDING, FULFILLED, COMPLETED, EXPIRED, CANCELLED

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column
    private LocalDateTime fulfilledAt;

    @Column
    private LocalDateTime completedAt;

    @Column
    private String createdBy; // Officer who created the request

    @Column
    private String holderDid; // Citizen's DID

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> sharedAttributes; // Only approved attributes

    @Column
    private String issuedCredentialId; // After successful issuance

    @Column
    private String errorMessage; // If any error occurred

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (status == null) {
            status = "PENDING";
        }
    }
}
