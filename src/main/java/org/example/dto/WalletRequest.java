package org.example.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class WalletRequest {

    @NotBlank(message = "DID is required")
    private String did;

    @NotBlank(message = "Password is required")
    private String password;
}