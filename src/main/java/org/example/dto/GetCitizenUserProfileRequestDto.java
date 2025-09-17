package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.util.UUID;

@Data
@Builder
public class GetCitizenUserProfileRequestDto {
    private UUID id;

    // Device Info
    private String deviceId;
    private String deviceType;
    private String os;
    private String ipAddress;
    private String location;
}
