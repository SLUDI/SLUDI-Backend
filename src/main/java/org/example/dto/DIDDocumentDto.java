package org.example.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonPropertyOrder({
        "id",
        "didVersion",
        "didCreated",
        "didUpdated",
        "publicKeys",
        "authentication",
        "services",
        "status",
        "proof",
        "blockchainTxId",
        "blockNumber"
})
public class DIDDocumentDto {
    private String id;
    private String didVersion;
    private String didCreated;
    private String didUpdated;
    private List<PublicKeyDto> publicKeys;
    private List<String> authentication;
    private List<ServiceDto> services;
    private String status;
    private ProofDataDto proof;
    private String blockchainTxId;
    private Long blockNumber;

    @JsonIgnore
    public boolean isValid() {
        return id != null && !id.isEmpty()
                && didVersion != null && !didVersion.isEmpty()
                && didCreated != null && !didCreated.isEmpty()
                && didUpdated != null && !didUpdated.isEmpty()
                && authentication != null && !authentication.isEmpty()
                && services != null
                && status != null && !status.isEmpty()
                && proof != null
                && blockchainTxId != null && !blockchainTxId.isEmpty()
                && blockNumber >= 0;
    }
}