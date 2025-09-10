package org.example.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

import java.util.UUID;

@Data
@Builder
@Schema(description = "Response returned after a user registration request")
public class UserRegistrationResponseDto {

    @Schema(
            description = "Unique identifier of the user",
            example = "550e8400-e29b-41d4-a716-446655440000"
    )
    private UUID userId;

    @Schema(
            description = "Decentralized Identifier (DID) assigned to the user",
            example = "did:example:123456789abcdefghi"
    )
    private String didId;

    @Schema(
            description = "Current status of the registration",
            example = "SUCCESS"
    )
    private String status;

    @Schema(
            description = "Additional information or error message",
            example = "User registered successfully"
    )
    private String message;

    @Schema(
            description = "Blockchain transaction ID related to DID registration",
            example = "0xabc123def456..."
    )
    private String blockchainTxId;
}
