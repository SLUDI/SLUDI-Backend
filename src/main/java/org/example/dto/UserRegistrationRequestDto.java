package org.example.dto;

import lombok.Builder;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
@Builder
public class UserRegistrationRequestDto {
    private PersonalInfoDto personalInfo;
    private ContactInfoDto contactInfo;
    private BiometricDataDto biometricData;
    private MultipartFile profilePhoto;
    private DeviceInfoDto deviceInfo;
}