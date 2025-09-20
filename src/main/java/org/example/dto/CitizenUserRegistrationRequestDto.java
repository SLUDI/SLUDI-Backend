package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CitizenUserRegistrationRequestDto {
    private PersonalInfoDto personalInfo;
    private ContactInfoDto contactInfo;

    @Builder.Default
    private List<SupportingDocumentRequestDto> supportingDocuments = new ArrayList<>();

    private SelectedDatesDto selectedDates;

    private DeviceInfoDto deviceInfo;
}