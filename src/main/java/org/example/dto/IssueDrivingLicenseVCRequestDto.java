package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;
import java.util.List;

@Data
@Builder
public class IssueDrivingLicenseVCRequestDto {
    private String did;
    private List<VehicleCategoryRequestDto> vehicleCategories;
    private String issuingAuthority;
    private String restrictions;
    private String endorsements;
    private Integer validityYears; // typically 5 years

    // Medical fitness
    private LocalDate medicalCheckDate;

    private List<SupportingDocumentRequestDto> supportingDocuments;
}