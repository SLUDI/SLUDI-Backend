package org.example.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class WalletVerificationRequestDto {
    @NotBlank(message = "DID is required")
    private String did;

    @NotBlank(message = "Signature is required")
    private String signature;
}

