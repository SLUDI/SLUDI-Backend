package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.enums.OrganizationStatus;
import org.example.enums.OrganizationType;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;


@Entity
@Table(name = "organizations")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Organization {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "org_code", unique = true, nullable = false, length = 50)
    private String orgCode;

    @Column(name = "name", nullable = false)
    private String name;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "template_id")
    private PermissionTemplate template;

    @Column(name = "registration_number", unique = true, length = 100)
    private String registrationNumber;

    @Column(name = "org_type", nullable = false, length = 50)
    @Enumerated(EnumType.STRING)
    private OrganizationType orgType;

    @Column(name = "sector", length = 50)
    private String sector;

    // Contact Information
    @Column(name = "contact_email")
    private String contactEmail;

    @Column(name = "contact_phone", length = 20)
    private String contactPhone;

    @Column(name = "address", columnDefinition = "TEXT")
    private String address;

    @Column(name = "city", length = 100)
    private String city;

    @Column(name = "postal_code", length = 20)
    private String postalCode;

    // Custom Permissions stored as JSONB
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "custom_permissions", columnDefinition = "jsonb")
    private CustomPermissions customPermissions;

    // Status Management
    @Column(name = "status", nullable = false, length = 20)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private OrganizationStatus status = OrganizationStatus.PENDING;

    // Blockchain Integration
    @Column(name = "blockchain_tx_id")
    private String blockchainTxId;

    @Column(name = "blockchain_block_number")
    private Long blockchainBlockNumber;

    @Column(name = "blockchain_timestamp")
    private LocalDateTime blockchainTimestamp;

    // Approval Workflow
    @Column(name = "created_by")
    private Long createdBy;

    @Column(name = "approved_by")
    private Long approvedBy;

    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    @Column(name = "suspended_by")
    private Long suspendedBy;

    @Column(name = "suspended_at")
    private LocalDateTime suspendedAt;

    @Column(name = "suspension_reason", columnDefinition = "TEXT")
    private String suspensionReason;

    // Metadata
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
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

    // Inner class for custom permissions
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CustomPermissions {
        private java.util.List<String> added;
        private java.util.List<String> removed;
    }
}