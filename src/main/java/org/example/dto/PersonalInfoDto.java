package org.example.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;

@Data
@Builder
@Schema(description = "Personal information")
public class PersonalInfoDto {

    @Schema(description = "Full name of the user")
    private String fullName;

    @Schema(description = "National Identity Card number")
    private String nic;

    @Schema(description = "Date of birth", example = "1990-01-01")
    private LocalDate dateOfBirth;

    private String citizenship;
    private String gender;
    private String nationality;

    @Schema(description = "Address details")
    private AddressDto address;
}
