package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
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
