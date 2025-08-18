package org.example.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class DidVerificationRequest {
    @NotBlank(message = "DID is required")
    @Pattern(
            regexp = "^did:sludi:[a-zA-Z0-9]{12,}$",
            message = "Invalid DID format")
    private String did;
}