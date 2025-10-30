package org.example.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class WalletVerificationRequestDto {
    @NotBlank(message = "DID is required")
    private String did;

    @NotBlank(message = "Signature is required")
    private String signature;
}

