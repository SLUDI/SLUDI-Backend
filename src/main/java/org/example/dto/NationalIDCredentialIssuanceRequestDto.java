package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
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