package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PersonalInfoDto {
    private String fullName;
    private String nic;
    private LocalDate dateOfBirth;
    private String citizenship;
    private String gender;
    private String nationality;
    private String bloodGroup;
    private AddressDto address;
}
