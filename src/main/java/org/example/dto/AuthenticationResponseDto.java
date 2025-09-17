package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.util.UUID;

@Data
@Builder
public class AuthenticationResponseDto {
    private UUID userId;
    private String didId;
    private String accessToken;
    private String refreshToken;
    private int expiresIn;
    private GetCitizenUserProfileResponseDto userProfile;
}
