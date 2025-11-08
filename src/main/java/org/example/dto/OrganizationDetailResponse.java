package org.example.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.entity.Organization;
import org.example.enums.OrganizationStatus;
import org.example.enums.OrganizationType;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OrganizationDetailResponse {

    private Long id;
    private String orgCode;
    private String name;
    private String registrationNumber;
    private OrganizationType orgType;
    private String sector;

    // Contact Information
    private String contactEmail;
    private String contactPhone;
    private String address;
    private String city;
    private String postalCode;

    // Template Information
    private PermissionTemplateResponse template;

    // Permissions
    private List<String> effectivePermissions;
    private CustomPermissionsResponse customPermissions;

    // Status
    private OrganizationStatus status;

    // Blockchain
    private String blockchainTxId;
    private Long blockchainBlockNumber;
    private LocalDateTime blockchainTimestamp;

    // Audit Trail
    private Long createdBy;
    private LocalDateTime createdAt;
    private Long approvedBy;
    private LocalDateTime approvedAt;
    private Long suspendedBy;
    private LocalDateTime suspendedAt;
    private String suspensionReason;
    private LocalDateTime updatedAt;

    // Statistics
    private Long totalUsers;
    private Long activeUsers;
    private Long totalRoles;
}

