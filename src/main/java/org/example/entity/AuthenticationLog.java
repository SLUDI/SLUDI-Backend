package org.example.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "authentication_logs")
public class AuthenticationLog {
    @Id
    private UUID id;

    private String userId;
    private String userDid;
    private String authType;
    private String authMethod;
    private String result;
    private String failureReason;
    private String ipAddress;

    @Column(columnDefinition = "TEXT")
    private String deviceInfo;

    private LocalDateTime attemptedAt;
    private LocalDateTime completedAt;
}
