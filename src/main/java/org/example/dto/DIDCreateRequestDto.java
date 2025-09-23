package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DIDCreateRequestDto {
    String nic;
    //private BiometricDataDto biometricData;
    private DeviceInfoDto deviceInfo;
}
