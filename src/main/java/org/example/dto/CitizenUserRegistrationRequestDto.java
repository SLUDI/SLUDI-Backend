package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
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

    private LocalDate selectedDate;

    private DeviceInfoDto deviceInfo;
}