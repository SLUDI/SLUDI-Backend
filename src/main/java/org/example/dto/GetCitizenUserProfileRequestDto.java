package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GetCitizenUserProfileRequestDto {
    private UUID id;

    // Device Info
    private String deviceId;
    private String deviceType;
    private String os;
    private String ipAddress;
    private String location;
}
