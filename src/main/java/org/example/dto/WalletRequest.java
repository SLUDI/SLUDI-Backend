package org.example.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class WalletRequest {

    @NotBlank(message = "DID is required")
    private String did;

    @NotBlank(message = "PublicKey is required")
    private String publicKey;
}