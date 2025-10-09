package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WalletDto {

    private String id;

    private String citizenUserId;

    private String didId;

    private List<WalletVerifiableCredentialDto> walletVerifiableCredentials;

    private LocalDateTime createdAt;
    private LocalDateTime lastAccessed;
    private String status;

}
