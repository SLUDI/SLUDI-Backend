package org.example.entity;

import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Embeddable
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Address {

    private String street;
    private String city;
    private String district;
    private String postalCode;
    private String divisionalSecretariat;
    private String gramaNiladhariDivision;
    private String province;

    public Address(String street, String city, String state, String postalCode) {
        this.street = street;
        this.city = city;
        this.province = state;
        this.postalCode = postalCode;
    }
}