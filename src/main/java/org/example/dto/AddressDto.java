package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
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
