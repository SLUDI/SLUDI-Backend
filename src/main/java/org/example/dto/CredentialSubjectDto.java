package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CredentialSubjectDto {
    private String id; // DID of the subject
    private String fullName;
    private String nic;
    private String dateOfBirth;
    private String citizenship;
    private String gender;
    private String nationality;
    private BiometricHashesDto biometricData;
    private AddressDto address;
    private String additionalAttributes; // JSON string for additional attributes
}
