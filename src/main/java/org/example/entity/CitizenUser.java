package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.enums.KYCStatus;
import org.example.enums.UserStatus;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "citizen_users")
public class CitizenUser {

    @Id
    private UUID id;

    @Column(unique = true, nullable = false)
    private String citizenCode;

    private String fullName;
    private String nic;
    private String age;
    private String email;
    private String phone;
    private String dateOfBirth;
    private String gender;
    private String nationality;
    private String citizenship;
    private String bloodGroup;

    @Embedded
    private Address address;

    @ElementCollection
    @CollectionTable(
            name = "citizen_supporting_documents",
            joinColumns = @JoinColumn(name = "citizen_user_id")
    )
    private List<SupportingDocument> supportingDocuments;


    @Enumerated(EnumType.STRING)
    private UserStatus status;

    @Enumerated(EnumType.STRING)
    private KYCStatus kycStatus;

    private String didId;
    private String publicKey;
    private String fingerprintIpfsHash;
    private String faceImageIpfsHash;
    private String signatureIpfsHash;
    private String profilePhotoIpfsHash;

    private String createdAt;
    private String updatedAt;
    private String lastLogin;

    @Builder.Default
    @OneToMany(mappedBy = "citizenUser", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<PublicKey> publicKeys = new ArrayList<>();

    @OneToOne(mappedBy = "citizenUser", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Wallet wallet;

    @Builder.Default
    @OneToMany(mappedBy = "citizenUser", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<UserPreferredDate> preferredDates = new ArrayList<>();

    @OneToOne(mappedBy = "citizenUser", cascade = CascadeType.ALL, orphanRemoval = true)
    private Appointment appointment;
}