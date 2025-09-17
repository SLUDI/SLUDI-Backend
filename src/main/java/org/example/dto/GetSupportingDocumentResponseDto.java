package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GetSupportingDocumentResponseDto {
    private String name;
    private String file;
    private String fileType;
    private String side;
}
