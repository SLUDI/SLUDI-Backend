package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialSignatureRequestDto {

    private String credentialId;

    private String credentialType; // CitizenRegistration, PoliceRecord, MedicalRecord, etc.

    private String subjectDid; // DID of the credential subject (citizen)

    private String signData;

    private String expirationDate; // Optional expiration date (ISO 8601)
}

