package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "citizen_users")
public class CitizenUser {

    public enum UserStatus { PENDING, ACTIVE, INACTIVE, DEACTIVATED }

    public enum KYCStatus { NOT_STARTED, IN_PROGRESS, VERIFIED, REJECTED }

    @Id
    private UUID id;

    private String fullName;
    private String nic;
    private String email;
    private String phone;
    private LocalDate dateOfBirth;
    private String gender;
    private String nationality;
    private String citizenship;

    @Embedded
    private Address address;

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
    private Long didCreationBlockNumber;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime lastLogin;

    @OneToOne(mappedBy = "citizenUser", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Wallet wallet;
}