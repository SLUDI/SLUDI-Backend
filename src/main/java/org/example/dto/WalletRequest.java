package org.example.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class WalletRequest {

    @NotBlank(message = "DID is required")
    private String did;

    @NotBlank(message = "PublicKey is required")
    private String publicKey;

    @NotBlank(message = "CSR PEM is required")
    private String csrPem;
}