package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class IssueDrivingLicenseVCRequestDto {
    private String sessionId; // Links to presentation request
    private List<VehicleCategoryRequestDto> vehicleCategories;
    private List<SupportingDocumentRequestDto> supportingDocuments;
    private Integer validityYears;
    private String issuingAuthority;
    private List<String> restrictions;
    private List<String> endorsements;
}