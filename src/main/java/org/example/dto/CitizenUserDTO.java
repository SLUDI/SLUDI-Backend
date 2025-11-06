package org.example.dto;

import lombok.Builder;
import lombok.Data;
import org.example.entity.Address;
import org.example.entity.CitizenUser;
import org.example.entity.SupportingDocument;
import org.example.enums.KYCStatus;
import org.example.enums.UserStatus;

import java.util.List;
import java.util.UUID;

@Data
@Builder
public class CitizenUserDTO {
    private UUID id;
    private String citizenCode;
    private String fullName;
    private String nic;
    private int age;
    private String email;
    private String phone;
    private String dateOfBirth;
    private String gender;
    private String nationality;
    private String citizenship;
    private String bloodGroup;
    private Address address;
    private List<SupportingDocument> supportingDocuments;
    private UserStatus status;
    private KYCStatus kycStatus;
    private String didId;
    private String publicKey;
    private String fingerprintIpfsHash;
    private String faceImageIpfsHash;
    private String signatureIpfsHash;
    private String profilePhotoIpfsHash;
    private String createdAt;
    private String updatedAt;
    private String lastLogin;
}
