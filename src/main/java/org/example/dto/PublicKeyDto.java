package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PublicKeyDto {
    private String id;
    private String type;
    private String controller;
    private String publicKeyBase58;
}
