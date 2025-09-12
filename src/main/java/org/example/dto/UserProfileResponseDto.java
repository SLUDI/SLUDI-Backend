package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
public class UserProfileResponseDto {
    private UUID userId;
    private String didId;
    private String fullName;
    private String nic;
    private String email;
    private String phone;
    private String dateOfBirth;
    private String gender;
    private String nationality;
    private AddressDto address;
    private String status;
    private String kycStatus;
    private String profilePhotoHash;
    private String createdAt;
    private String updatedAt;
    private String lastLogin;
}
