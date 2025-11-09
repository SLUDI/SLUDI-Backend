package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrganizationLoginResponseDto {

    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private Long expiresIn;

    // User details
    private Long userId;
    private String username;
    private String email;
    private String employeeId;
    private String firstName;
    private String lastName;

    // Organization details
    private Long organizationId;
    private String organizationName;
    private String organizationCode;

    // Role details
    private Long roleId;
    private String roleCode;
    private Boolean isAdmin;
    private List<String> permissions;

    private LocalDateTime loginTime;
}
