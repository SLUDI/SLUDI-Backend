package org.example.dto;

import lombok.Builder;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
@Builder
public class BiometricDataDto {
    private byte[] fingerprint;
    private MultipartFile faceImage;
    private byte[] signature;
}
