package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DeviceInfoDto {
    private String deviceId;
    private String deviceType;
    private String os;
    private String ipAddress;
    private String location;
}
