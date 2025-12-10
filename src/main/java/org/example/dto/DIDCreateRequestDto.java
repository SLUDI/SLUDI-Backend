package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DIDCreateRequestDto {
    String nic;
    //private BiometricDataDto biometricData;
    private DeviceInfoDto deviceInfo;
}
