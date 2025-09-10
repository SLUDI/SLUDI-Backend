package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SupportingDocumentDto {
    private String name;
    private String ipfsCid;
    private String fileType;
}
