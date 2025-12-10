package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CitizenUserProfileUpdateRequestDto {
    private String email;
    private String phone;
    private AddressDto address;
    private String newPublicKey;
    private List<SupportingDocumentRequestDto> newSupportingDocuments;
    MultipartFile profilePhoto;
    private DeviceInfoDto deviceInfo;
}
