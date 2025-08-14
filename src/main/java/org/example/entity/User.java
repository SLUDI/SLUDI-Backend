package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User {
    public enum UserStatus {
        PENDING, ACTIVE, SUSPENDED, DEACTIVATED
    }

    public enum KYCStatus {
        NOT_STARTED, IN_PROGRESS, VERIFIED, REJECTED
    }

    @Id
    private UUID id;

    private String fullName;
    private String nic;
    private String email;
    private String phone;
    private LocalDate dateOfBirth;
    private String gender;
    private String nationality;

    @Column(columnDefinition = "TEXT")
    private String addressJson;

    @Enumerated(EnumType.STRING)
    private UserStatus status;

    @Enumerated(EnumType.STRING)
    private KYCStatus kycStatus;

    private String didId;
    private String fingerprintIpfsHash;
    private String faceImageIpfsHash;
    private String signatureIpfsHash;
    private String profilePhotoIpfsHash;
    private String blockchainTxId;
    private String didCreationBlockNumber;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime lastLogin;
}