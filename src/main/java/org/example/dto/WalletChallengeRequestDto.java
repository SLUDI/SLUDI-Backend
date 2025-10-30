package org.example.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class WalletChallengeRequestDto {
    @NotBlank(message = "DID is required")
    private String did;
}

