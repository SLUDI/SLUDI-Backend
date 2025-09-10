package org.example.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@Schema(description = "Address details")
public class AddressDto {
    private String street;
    private String city;
    private String district;
    private String postalCode;
    private String divisionalSecretariat;
    private String gramaNiladhariDivision;
    private String state;
    private String country;
}
