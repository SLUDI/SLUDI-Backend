package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class IssueVCRequestDto {
    private String did;
    private String credentialType;
    private List<SupportingDocumentRequestDto> supportingDocuments;
}
