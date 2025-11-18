package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class DrivingLicenseCredentialSubject {
    private String id;
    private String fullName;
    private String nic;
    private String dateOfBirth;
    private String address;
    private String profilePhoto;

    // Driving-specific fields
    private String licenseNumber;
    private String issueDate;
    private String expiryDate;
    private List<VehicleCategory> authorizedVehicles;
    private String issuingAuthority;
    private List<String> restrictions;
    private List<String> endorsements;
    private String bloodGroup;
}
