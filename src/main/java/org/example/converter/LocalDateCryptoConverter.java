package org.example.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.example.security.CryptographyService;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@Converter(autoApply = false)
@Component
public class LocalDateCryptoConverter implements AttributeConverter<LocalDate, String> {

    private final CryptographyService cryptographyService;
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE;

    public LocalDateCryptoConverter(CryptographyService cryptographyService) {
        this.cryptographyService = cryptographyService;
    }

    @Override
    public String convertToDatabaseColumn(LocalDate attribute) {
        if (attribute == null) return null;
        String plainText = attribute.format(FORMATTER);
        return cryptographyService.encryptData(plainText);
    }

    @Override
    public LocalDate convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.isBlank()) return null;
        try {
            String decrypted = cryptographyService.decryptData(dbData);
            return LocalDate.parse(decrypted, FORMATTER);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to decrypt or parse dateOfBirth", e);
        }
    }
}