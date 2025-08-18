package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CitizenRegistrationChaincode {
    private String userId;
    private String fullName;
    private String dateOfBirth;
    private String nic;
    private String fingerprintHash;
    private String faceImageHash;
}