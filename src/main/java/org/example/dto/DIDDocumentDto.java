package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class DIDDocumentDto {
    private String id;
    private String didVersion;
    private String didCreated;
    private String didUpdated;
    private List<PublicKeyDto> publicKey;
    private List<String> authentication;
    private List<ServiceDto> service;
    private String status; // active, deactivated, revoked
    private ProofDataDto proof;
}
