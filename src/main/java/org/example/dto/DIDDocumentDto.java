package org.example.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
@Schema(description = "Decentralized Identifier (DID) Document")
public class DIDDocumentDto {

    @Schema(description = "The DID of the user", example = "did:sludi:123456789")
    private String id;

    @Schema(description = "Version of the DID", example = "1.0")
    private String didVersion;

    @Schema(description = "DID creation timestamp", example = "2025-09-11T12:34:56Z")
    private String didCreated;

    @Schema(description = "Last update timestamp of the DID", example = "2025-09-11T12:34:56Z")
    private String didUpdated;

    @Schema(description = "Public keys associated with this DID")
    private List<PublicKeyDto> publicKey;

    @Schema(description = "Authentication methods", example = "[\"did:sludi:123456789#key-1\"]")
    private List<String> authentication;

    @Schema(description = "Associated services (endpoints, wallet, etc.)")
    private List<ServiceDto> service;

    @Schema(description = "DID status", allowableValues = {"active", "deactivated", "revoked"})
    private String status;

    @Schema(description = "Proof of signature and integrity of the DID Document")
    private ProofDataDto proof;

    @Schema(description = "Blockchain transaction ID where this DID was anchored")
    private String blockchainTxId;

    @Schema(description = "Block number in blockchain where this DID was anchored")
    private Long blockNumber;
}
