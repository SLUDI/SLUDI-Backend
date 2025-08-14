package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;

@Data
@Builder
public class PersonalInfoDto {
    private String fullName;
    private String nic;
    private LocalDate dateOfBirth;
    private String gender;
    private AddressDto address;
}
