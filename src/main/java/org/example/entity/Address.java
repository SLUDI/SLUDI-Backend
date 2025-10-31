package org.example.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.converter.CryptoConverter;

@Embeddable
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Address {

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
    private String street;

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
    private String city;

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
    private String district;

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
    private String postalCode;

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
    private String divisionalSecretariat;

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
    private String gramaNiladhariDivision;

    @Convert(converter = CryptoConverter.class)
    @Column(columnDefinition = "TEXT")
    private String province;

    public Address(String street, String city, String state, String postalCode) {
        this.street = street;
        this.city = city;
        this.province = state;
        this.postalCode = postalCode;
    }
}