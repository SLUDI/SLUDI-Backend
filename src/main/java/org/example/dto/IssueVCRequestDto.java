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
public class IssueVCRequestDto {
    private String did;
    private String credentialType;
    private List<SupportingDocumentRequestDto> supportingDocuments;
}
