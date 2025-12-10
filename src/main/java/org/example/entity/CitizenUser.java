package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.converter.CryptoConverter;
import org.example.converter.LocalDateCryptoConverter;
import org.example.enums.VerificationStatus;
import org.example.enums.UserStatus;
import org.example.utils.HashUtil;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDate;
import java.time.Period;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "citizen_users")
public class CitizenUser implements UserDetails {

    @Id
    private UUID id;

    @Column(unique = true, nullable = false)
    private String citizenCode;

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
    private String fullName;

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
    private String nic;

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
    private String email;

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
    private String phone;

    @Column(name = "date_of_birth", columnDefinition = "TEXT")
    @Convert(converter = LocalDateCryptoConverter.class)
    private LocalDate dateOfBirth;

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
    private String gender;

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
    private String nationality;

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
    private String citizenship;

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
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
    private VerificationStatus verificationStatus;

    private String didId;
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

    @Column(name = "nic_hash", unique = true, length = 64)
    private String nicHash;

    @Column(name = "email_hash", unique = true, length = 64)
    private String emailHash;

    @Column(name = "did_id_hash", unique = true, length = 64)
    private String didIdHash;

    public void addPublicKey(PublicKey key) {
        key.setCitizenUser(this);
        this.publicKeys.add(key);
    }


    @PrePersist
    @PreUpdate
    private void generateHashes() {
        if (this.nic != null) {
            this.nicHash = HashUtil.sha256(this.nic);
        }
        if (this.email != null) {
            this.emailHash = HashUtil.sha256(this.email);
        }
        if (this.didId != null) {
            this.didIdHash = HashUtil.sha256(this.didId);
        }
    }

    @Transient
    public int getAge() {
        if (dateOfBirth == null) {
            return 0;
        }
        return Period.between(dateOfBirth, LocalDate.now()).getYears();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return didId;
    }
}