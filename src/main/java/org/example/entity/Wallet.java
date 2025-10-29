package org.example.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.persistence.*;
import org.example.enums.WalletStatus;

import java.time.LocalDateTime;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "wallets")
public class Wallet {

    @Id
    private String id;

    @OneToOne
    @JoinColumn(name = "citizen_user_id", referencedColumnName = "id")
    private CitizenUser citizenUser;

    private String didId;

    @Column(columnDefinition = "TEXT")
    private String certificatePem;

    @Column(columnDefinition = "TEXT")
    private String publicKeyPem;

    private String mspId;

    private LocalDateTime createdAt;
    private LocalDateTime lastAccessed;
    private WalletStatus status;
}
