package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NationalIDCredentialIssuanceRequestDto {
    private String subjectDID;
    private String credentialType;
    private String fullName;
    private String nic;
    private String dateOfBirth;
    private String citizenship;
    private String gender;
    private String nationality;
    private String fingerprintHash;
    private String faceImageHash;
    private AddressDto address;
}