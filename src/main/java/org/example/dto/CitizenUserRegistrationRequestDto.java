package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class CitizenUserRegistrationRequestDto {
    private PersonalInfoDto personalInfo;
    private ContactInfoDto contactInfo;
    private List<SupportingDocument> supportingDocuments;
    private DeviceInfoDto deviceInfo;
}