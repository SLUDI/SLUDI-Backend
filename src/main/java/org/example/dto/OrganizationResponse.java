package org.example.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.entity.Organization;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OrganizationResponse {
    private Long id;
    private String orgCode;
    private String name;
    private String registrationNumber;
    private Organization.OrganizationType orgType;
    private String sector;

    // Contact Information
    private String contactEmail;
    private String contactPhone;
    private String address;
    private String city;
    private String postalCode;

    // Status
    private Organization.OrganizationStatus status;

    // Template Information (basic)
    private String templateName;
    private Long templateId;
    // Timestamps
    private LocalDateTime createdAt;
    private LocalDateTime approvedAt;
}
