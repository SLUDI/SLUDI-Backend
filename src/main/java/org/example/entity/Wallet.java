package org.example.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

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

    @Embedded
    private WalletCredential credentials;

    @Builder.Default
    @ElementCollection
    @CollectionTable(name = "wallet_credentials", joinColumns = @JoinColumn(name = "wallet_id"))
    @Column(name = "encrypted_vc", columnDefinition = "TEXT")
    private List<String> encryptedCredentials = new ArrayList<>();

    private LocalDateTime createdAt;
    private LocalDateTime lastAccessed;
    private String status;

    public void addCredential(String encryptedVC) {
        if (this.encryptedCredentials == null) {
            this.encryptedCredentials = new ArrayList<>();
        }
        this.encryptedCredentials.add(encryptedVC);
    }
}
