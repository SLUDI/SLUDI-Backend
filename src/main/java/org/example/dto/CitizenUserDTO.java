package org.example.dto;

import lombok.Builder;
import lombok.Data;
import org.example.entity.Address;
import org.example.entity.CitizenUser;
import org.example.entity.SupportingDocument;

import java.util.List;
import java.util.UUID;

@Data
@Builder
public class CitizenUserDTO {
    private UUID id;
    private String citizenCode;
    private String fullName;
    private String nic;
    private String age;
    private String email;
    private String phone;
    private String dateOfBirth;
    private String gender;
    private String nationality;
    private String citizenship;
    private String bloodGroup;
    private Address address;
    private List<SupportingDocument> supportingDocuments;
    private CitizenUser.UserStatus status;
    private CitizenUser.KYCStatus kycStatus;
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
