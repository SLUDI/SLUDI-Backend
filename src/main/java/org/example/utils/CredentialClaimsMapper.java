package org.example.utils;

import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Utility class to convert CredentialSubject to Claims Map
 * for use with DigitalSignatureService
 */
@Slf4j
@Component
public class CredentialClaimsMapper {

    /**
     * Convert CredentialSubject to Claims Map for signing
     *
     * @param credentialSubject The structured credential subject
     * @return Map of claims suitable for signing
     */
    public Map<String, Object> convertToClaimsMap(CredentialSubject credentialSubject) {
        log.debug("Converting CredentialSubject to claims map for DID: {}", credentialSubject.getId());

        Map<String, Object> claims = new HashMap<>();

        // Basic identity claims
        addClaimIfNotNull(claims, "id", credentialSubject.getId());
        addClaimIfNotNull(claims, "fullName", credentialSubject.getFullName());
        addClaimIfNotNull(claims, "nic", credentialSubject.getNic());
        addClaimIfNotNull(claims, "age", credentialSubject.getAge());
        addClaimIfNotNull(claims, "dateOfBirth", credentialSubject.getDateOfBirth());
        addClaimIfNotNull(claims, "citizenship", credentialSubject.getCitizenship());
        addClaimIfNotNull(claims, "gender", credentialSubject.getGender());
        addClaimIfNotNull(claims, "nationality", credentialSubject.getNationality());
        addClaimIfNotNull(claims, "bloodGroup", credentialSubject.getBloodGroup());

        // Biometric data (as nested object)
        if (credentialSubject.getBiometricData() != null) {
            Map<String, String> biometricClaims = new HashMap<>();
            addStringClaimIfNotNull(biometricClaims, "fingerprintHash",
                    credentialSubject.getBiometricData().getFingerprintHash());
            addStringClaimIfNotNull(biometricClaims, "faceImageHash",
                    credentialSubject.getBiometricData().getFaceImageHash());

            if (!biometricClaims.isEmpty()) {
                claims.put("biometricData", biometricClaims);
            }
        }

        // Address data (as nested object)
        if (credentialSubject.getAddress() != null) {
            Map<String, String> addressClaims = convertAddressToMap(credentialSubject.getAddress());
            if (!addressClaims.isEmpty()) {
                claims.put("address", addressClaims);
            }
        }

        log.debug("Converted {} claims from CredentialSubject", claims.size());
        return claims;
    }

    /**
     * Convert AddressDto to Map
     */
    private Map<String, String> convertAddressToMap(AddressDto address) {
        Map<String, String> addressMap = new HashMap<>();

        addStringClaimIfNotNull(addressMap, "street", address.getStreet());
        addStringClaimIfNotNull(addressMap, "city", address.getCity());
        addStringClaimIfNotNull(addressMap, "district", address.getDistrict());
        addStringClaimIfNotNull(addressMap, "postalCode", address.getPostalCode());
        addStringClaimIfNotNull(addressMap, "divisionalSecretariat", address.getDivisionalSecretariat());
        addStringClaimIfNotNull(addressMap, "gramaNiladhariDivision", address.getGramaNiladhariDivision());
        addStringClaimIfNotNull(addressMap, "province", address.getProvince());

        return addressMap;
    }

    /**
     * Add claim only if value is not null
     */
    private void addClaimIfNotNull(Map<String, Object> claims, String key, Object value) {
        if (value != null) {
            claims.put(key, value);
        }
    }

    /**
     * Add string claim only if value is not null
     */
    private void addStringClaimIfNotNull(Map<String, String> claims, String key, String value) {
        if (value != null) {
            claims.put(key, value);
        }
    }

    /**
     * Alternative: Flatten nested structures into single-level claims
     * Useful for simpler claim structures
     */
    public Map<String, Object> convertToFlatClaimsMap(CredentialSubject credentialSubject) {
        log.debug("Converting CredentialSubject to flat claims map");

        Map<String, Object> claims = new HashMap<>();

        // Basic identity claims
        addClaimIfNotNull(claims, "id", credentialSubject.getId());
        addClaimIfNotNull(claims, "fullName", credentialSubject.getFullName());
        addClaimIfNotNull(claims, "nic", credentialSubject.getNic());
        addClaimIfNotNull(claims, "age", credentialSubject.getAge());
        addClaimIfNotNull(claims, "dateOfBirth", credentialSubject.getDateOfBirth());
        addClaimIfNotNull(claims, "citizenship", credentialSubject.getCitizenship());
        addClaimIfNotNull(claims, "gender", credentialSubject.getGender());
        addClaimIfNotNull(claims, "nationality", credentialSubject.getNationality());
        addClaimIfNotNull(claims, "bloodGroup", credentialSubject.getBloodGroup());

        // Flatten biometric data
        if (credentialSubject.getBiometricData() != null) {
            addClaimIfNotNull(claims, "fingerprintHash",
                    credentialSubject.getBiometricData().getFingerprintHash());
            addClaimIfNotNull(claims, "faceImageHash",
                    credentialSubject.getBiometricData().getFaceImageHash());
        }

        // Flatten address data with prefixes
        if (credentialSubject.getAddress() != null) {
            AddressDto addr = credentialSubject.getAddress();
            addClaimIfNotNull(claims, "address_street", addr.getStreet());
            addClaimIfNotNull(claims, "address_city", addr.getCity());
            addClaimIfNotNull(claims, "address_district", addr.getDistrict());
            addClaimIfNotNull(claims, "address_postalCode", addr.getPostalCode());
            addClaimIfNotNull(claims, "address_divisionalSecretariat", addr.getDivisionalSecretariat());
            addClaimIfNotNull(claims, "address_gramaNiladhariDivision", addr.getGramaNiladhariDivision());
            addClaimIfNotNull(claims, "address_province", addr.getProvince());
        }

        log.debug("Converted {} flat claims from CredentialSubject", claims.size());
        return claims;
    }

    /**
     * Create minimal claims (only essential information)
     * Useful for privacy-preserving scenarios
     */
    public Map<String, Object> convertToMinimalClaimsMap(CredentialSubject credentialSubject) {
        Map<String, Object> claims = new HashMap<>();

        // Only essential identity fields
        addClaimIfNotNull(claims, "id", credentialSubject.getId());
        addClaimIfNotNull(claims, "nic", credentialSubject.getNic());
        addClaimIfNotNull(claims, "fullName", credentialSubject.getFullName());
        addClaimIfNotNull(claims, "dateOfBirth", credentialSubject.getDateOfBirth());
        addClaimIfNotNull(claims, "nationality", credentialSubject.getNationality());

        return claims;
    }

    /**
     * Convert claims map back to CredentialSubject
     * Useful for verification
     */
    public CredentialSubject convertFromClaimsMap(Map<String, Object> claims) {
        CredentialSubject.CredentialSubjectBuilder builder = CredentialSubject.builder();

        // Extract basic fields
        builder.id(getStringClaim(claims, "id"));
        builder.fullName(getStringClaim(claims, "fullName"));
        builder.nic(getStringClaim(claims, "nic"));
        builder.age(getIntegerClaim(claims, "age"));
        builder.dateOfBirth(getStringClaim(claims, "dateOfBirth"));
        builder.citizenship(getStringClaim(claims, "citizenship"));
        builder.gender(getStringClaim(claims, "gender"));
        builder.nationality(getStringClaim(claims, "nationality"));
        builder.bloodGroup(getStringClaim(claims, "bloodGroup"));

        // Extract biometric data if present
        if (claims.containsKey("biometricData")) {
            @SuppressWarnings("unchecked")
            Map<String, String> bioData = (Map<String, String>) claims.get("biometricData");
            builder.biometricData(BiometricHashesDto.builder()
                    .fingerprintHash(bioData.get("fingerprintHash"))
                    .faceImageHash(bioData.get("faceImageHash"))
                    .build());
        }

        // Extract address if present
        if (claims.containsKey("address")) {
            @SuppressWarnings("unchecked")
            Map<String, String> addrData = (Map<String, String>) claims.get("address");
            builder.address(AddressDto.builder()
                    .street(addrData.get("street"))
                    .city(addrData.get("city"))
                    .district(addrData.get("district"))
                    .postalCode(addrData.get("postalCode"))
                    .divisionalSecretariat(addrData.get("divisionalSecretariat"))
                    .gramaNiladhariDivision(addrData.get("gramaNiladhariDivision"))
                    .province(addrData.get("province"))
                    .build());
        }

        return builder.build();
    }

    // Helper methods for type-safe extraction

    private String getStringClaim(Map<String, Object> claims, String key) {
        Object value = claims.get(key);
        return value != null ? value.toString() : null;
    }

    private Integer getIntegerClaim(Map<String, Object> claims, String key) {
        Object value = claims.get(key);
        if (value == null) return null;
        if (value instanceof Integer) return (Integer) value;
        try {
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            log.warn("Failed to parse integer claim: {}", key);
            return null;
        }
    }
}