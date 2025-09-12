package org.example.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class IssueIdentityVCRequestDto {
    private String did;
    private String credentialType;
    private List<SupportingDocument> supportingDocuments;
}
