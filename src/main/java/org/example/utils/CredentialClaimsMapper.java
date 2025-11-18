package org.example.utils;

import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
        addClaimIfNotNull(claims, "profilePhoto", credentialSubject.getProfilePhotoHash());

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
     * Convert DrivingLicenseCredentialSubject to Claims Map for signing
     *
     * @param drivingLicenseSubject The structured driving license credential subject
     * @return Map of claims suitable for signing
     */
    public Map<String, Object> convertLicenseClaimsMap(DrivingLicenseCredentialSubject drivingLicenseSubject) {
        log.debug("Converting DrivingLicenseCredentialSubject to claims map for DID: {}",
                drivingLicenseSubject.getId());

        Map<String, Object> claims = new HashMap<>();

        // Basic identity claims
        addClaimIfNotNull(claims, "id", drivingLicenseSubject.getId());
        addClaimIfNotNull(claims, "fullName", drivingLicenseSubject.getFullName());
        addClaimIfNotNull(claims, "nic", drivingLicenseSubject.getNic());
        addClaimIfNotNull(claims, "dateOfBirth", drivingLicenseSubject.getDateOfBirth());
        addClaimIfNotNull(claims, "address", drivingLicenseSubject.getAddress());
        addClaimIfNotNull(claims, "profilePhoto", drivingLicenseSubject.getProfilePhoto());
        addClaimIfNotNull(claims, "bloodGroup", drivingLicenseSubject.getBloodGroup());

        // Driving license specific claims
        addClaimIfNotNull(claims, "licenseNumber", drivingLicenseSubject.getLicenseNumber());
        addClaimIfNotNull(claims, "issueDate", drivingLicenseSubject.getIssueDate() != null ?
                drivingLicenseSubject.getIssueDate().toString() : null);
        addClaimIfNotNull(claims, "expiryDate", drivingLicenseSubject.getExpiryDate() != null ?
                drivingLicenseSubject.getExpiryDate().toString() : null);
        addClaimIfNotNull(claims, "issuingAuthority", drivingLicenseSubject.getIssuingAuthority());
        addClaimIfNotNull(claims, "restrictions", drivingLicenseSubject.getRestrictions());
        addClaimIfNotNull(claims, "endorsements", drivingLicenseSubject.getEndorsements());

        // Authorized vehicles (as list of objects)
        if (drivingLicenseSubject.getAuthorizedVehicles() != null &&
                !drivingLicenseSubject.getAuthorizedVehicles().isEmpty()) {

            List<Map<String, Object>> vehiclesList = new ArrayList<>();

            for (VehicleCategory vehicle : drivingLicenseSubject.getAuthorizedVehicles()) {
                Map<String, Object> vehicleMap = new HashMap<>();
                addClaimIfNotNull(vehicleMap, "category", vehicle.getCategory());
                addClaimIfNotNull(vehicleMap, "validFrom", vehicle.getValidFrom() != null ?
                        vehicle.getValidFrom().toString() : null);
                addClaimIfNotNull(vehicleMap, "validUntil", vehicle.getValidUntil() != null ?
                        vehicle.getValidUntil().toString() : null);
                addClaimIfNotNull(vehicleMap, "restrictions", vehicle.getRestrictions());

                vehiclesList.add(vehicleMap);
            }

            claims.put("authorizedVehicles", vehiclesList);
        }

        log.debug("Converted {} claims from DrivingLicenseCredentialSubject", claims.size());
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