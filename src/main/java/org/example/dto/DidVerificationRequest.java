package org.example.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DidVerificationRequest {
    @NotBlank(message = "DID is required")
    @Pattern(
            regexp = "^[0-9]{12}$",
            message = "Invalid DID format. Expected exactly 12 digits"
    )
    private String did;
}