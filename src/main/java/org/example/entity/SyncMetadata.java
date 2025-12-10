package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "sync_metadata")
public class SyncMetadata {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String entityType; // DID or VC

    @Column(nullable = false)
    private String entityId; // DID ID or Credential ID

    @Column(nullable = false)
    private String blockchainTxId;

    private Long blockNumber;

    @Column(nullable = false)
    private LocalDateTime lastSyncedAt;

    @Column(nullable = false)
    private String syncStatus; // SYNCED, PENDING, FAILED

    @Column(columnDefinition = "TEXT")
    private String errorMessage;

    private Integer retryCount;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
