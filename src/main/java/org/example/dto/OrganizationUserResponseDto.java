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
public class OrganizationUserResponseDto {
    private Long userId;
    private String employeeId;
    private String email;
    private String username;
    private String firstName;
    private String lastName;
    private String phone;
    private Long organizationId;
    private String organizationName;
    private String organizationCode;
    private String did;
    private String department;
    private String designation;
    private String jobTitle;
    private Long roleId;
    private String roleCode;
    private List<String> permissions;
    private Long createdBy;
    private String status;
    private String verificationStatus;
    private String isActive;
    private String fabricUserId;
    private String fabricEnrollmentId;
    private Boolean isEnrolledOnBlockchain;
    private LocalDateTime enrollmentDate;
    private Long approvedBy;
    private LocalDateTime suspendedAt;
    private Long suspendedBy;
    private String suspensionReason;
    private LocalDateTime createdAt;
    private LocalDateTime approvedAt;
}
