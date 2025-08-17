package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Embeddable
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialSubject {

    private String id; // DID of the subject
    private String fullName;
    private String nic;
    private String dateOfBirth;
    private String citizenship;
    private String gender;
    private String nationality;

    @Embedded
    private BiometricHashes biometricHashes;

    @Embedded
    private Address address;

    @Column(name = "additional_attributes", columnDefinition = "TEXT")
    private String additionalAttributes;
}
