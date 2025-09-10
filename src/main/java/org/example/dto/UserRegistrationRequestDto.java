package org.example.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
@Builder
@Schema(description = "User registration request")
public class UserRegistrationRequestDto {

    @Schema(description = "Personal information of the user", required = true)
    private PersonalInfoDto personalInfo;

    @Schema(description = "Contact information of the user", required = true)
    private ContactInfoDto contactInfo;

    @Schema(description = "Profile photo of the user", type = "string", format = "binary", required = true)
    private MultipartFile profilePhoto;

    @Schema(description = "Device information of the user")
    private DeviceInfoDto deviceInfo;
}