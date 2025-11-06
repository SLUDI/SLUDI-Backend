package org.example.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.persistence.*;

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

    private LocalDateTime createdAt;
    private LocalDateTime lastAccessed;
    private String status;
}
