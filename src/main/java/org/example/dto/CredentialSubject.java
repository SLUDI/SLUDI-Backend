package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;

@Data
@Builder
public class CredentialSubject {
    private String id; // DID of the subject
    private String fullName;
    private String nic;
    private LocalDate dateOfBirth;
    private String citizenship;
    private String gender;
    private String nationality;
    private BiometricHashesDto biometricData;
    private AddressDto address;
}
