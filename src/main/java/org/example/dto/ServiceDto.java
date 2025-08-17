package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ServiceDto {
    private String id;
    private String type;
    private String serviceEndpoint;
}
