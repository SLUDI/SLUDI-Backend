package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SupportingDocumentResponseDto {
    private String name;
    private String ipfsCid;
    private String fileType;
    private String side;
}
