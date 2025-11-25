package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationRequestDto {
    private String identifierType;
    private String identifier;
    private BiometricInfoDto biometric;
    private DeviceInfoDto deviceInfo;
}
