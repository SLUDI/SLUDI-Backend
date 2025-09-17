package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceInfoDto {
    private String deviceId;
    private String deviceType;
    private String os;
    private String ipAddress;
    private String location;
}
