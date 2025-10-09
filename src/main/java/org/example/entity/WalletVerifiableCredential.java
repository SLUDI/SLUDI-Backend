package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "wallet_verifiable_credentials")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WalletVerifiableCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "wallet_id")
    private Wallet wallet;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "credential_id")
    private VerifiableCredential verifiableCredential;

    @Column(name = "encrypted_vc", columnDefinition = "TEXT", nullable = false)
    private String encryptedCredential;

    @Column(name = "added_at")
    private LocalDateTime addedAt;

    @Builder.Default
    @Column(name = "is_verified")
    private Boolean verified = false;
}

