package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AddressDto {
    private String street;
    private String city;
    private String district;
    private String postalCode;
    private String divisionalSecretariat;
    private String gramaNiladhariDivision;
    private String province;
}
