package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthenticationRequestDto {
    private String identifierType;
    private String identifier;
    private BiometricInfoDto biometric;
    private DeviceInfoDto deviceInfo;
}
