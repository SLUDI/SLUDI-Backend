package org.example.dto;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.entity.Organization;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CreateOrganizationRequest {
    @NotBlank(message = "Organization name is required")
    @Size(max =255, message = "Name must not exceed 255 characters")
    private String name;

    @NotNull(message = "Template ID is required")
    private Long templateId;

    @Size(max = 100, message = "Registration number must not exceed 100 characters")
    private String registrationNumber;

    @NotNull(message = "Organization type is required")
    private Organization.OrganizationType organizationType;

    @Size(max = 50, message = "Sector must not exceed 50 characters")
    private String sector;

    @Email(message = "Invalid email format")
    private String contactEmail;

    @Pattern(regexp = "^[+]?[0-9]{10,15}$", message = "Invalid phone number")
    private String contactPhone;

    private String address;

    @Size(max = 100, message = "City must not exceed 100 characters")
    private String city;

    @Size(max = 20, message = "Postal code must not exceed 20 characters")
    private String postalCode;

}
