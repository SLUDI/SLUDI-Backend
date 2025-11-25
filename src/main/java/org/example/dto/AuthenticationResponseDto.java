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
public class AuthenticationResponseDto {
    private UUID userId;
    private String didId;
    private String accessToken;
    private String refreshToken;
    private int expiresIn;
    private GetCitizenUserProfileResponseDto userProfile;
}
