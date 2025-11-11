package org.example.entity;

import jakarta.persistence.*;
import lombok.*;
import org.example.enums.OnboardingStatus;

import java.time.LocalDateTime;

@Entity
@Table(name = "organization_onboarding")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OrganizationOnboarding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    // Link to organization
    @OneToOne
    @JoinColumn(name = "organization_id", nullable = false, unique = true)
    private Organization organization;

    // Fabric Network Configuration
    @Column(name = "msp_id", unique = true, length = 100)
    private String mspId; // e.g., "Org2MSP", "Org3MSP"

    @Column(name = "peer_endpoint")
    private String peerEndpoint; // e.g., "localhost:9051"

    @Column(name = "ca_endpoint")
    private String caEndpoint; // Certificate Authority endpoint

    @Column(name = "orderer_endpoint")
    private String ordererEndpoint;

    // Crypto Materials Storage (paths)
    @Column(name = "crypto_config_path")
    private String cryptoConfigPath; // Path to crypto materials

    @Column(name = "wallet_path")
    private String walletPath;

    @Column(name = "network_path")
    private String networkPath;

    @Column(name = "onboarding_status")
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private OnboardingStatus onboardingStatus = OnboardingStatus.INITIATED;

    @Column(name = "provisioned_at")
    private LocalDateTime provisionedAt;

    @Column(name = "activated_at")
    private LocalDateTime activatedAt;

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
}