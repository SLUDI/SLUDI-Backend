package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

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
    private String bloodGroup;
    private BiometricHashesDto biometricData;
    private AddressDto address;
}
