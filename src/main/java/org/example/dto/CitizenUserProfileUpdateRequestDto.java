package org.example.dto;

import lombok.Builder;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Data
@Builder
public class CitizenUserProfileUpdateRequestDto {
    private String email;
    private String phone;
    private AddressDto address;
    private String newPublicKey;
    private List<MultipartFile> newDocuments;
    MultipartFile profilePhoto;
    private DeviceInfoDto deviceInfo;
}
