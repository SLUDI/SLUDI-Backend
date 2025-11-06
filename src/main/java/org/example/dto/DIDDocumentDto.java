package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
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
}
