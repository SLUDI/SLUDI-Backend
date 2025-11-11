package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrganizationUserRequestDto {
    private Long organizationId;
    private String email;
    private String username;
    private String firstName;
    private String lastName;
    private String phone;
    private Long roleId;
    private String password;
    private String did;
    private String department;
    private String designation;
    private String jobTitle;
    private String createdBy;
}
