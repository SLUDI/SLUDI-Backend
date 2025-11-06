package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class GetCitizenUserProfileResponseDto {
    private UUID userId;
    private String citizenCode;
    private String fullName;
    private String nic;
    private int age;
    private String email;
    private String phone;
    private LocalDate dateOfBirth;
    private String gender;
    private String nationality;
    private AddressDto address;
    private String status;
    private String kycStatus;

    @Builder.Default
    private List<GetSupportingDocumentResponseDto> supportingDocumentList = new ArrayList<>();

    private String createdAt;
    private String updatedAt;
    private String lastLogin;
}
