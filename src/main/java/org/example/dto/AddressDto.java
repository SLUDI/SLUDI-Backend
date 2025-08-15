package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AddressDto {
    private String street;
    private String city;
    private String state;
    private String postalCode;
    private String country;
    private String district;
    private String divisionalSecretariat;
    private String gramaNiladhariDivision;
}
