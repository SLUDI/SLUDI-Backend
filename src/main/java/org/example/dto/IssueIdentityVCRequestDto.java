package org.example.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
@Schema(description = "Request DTO for Issuing an Identity Verifiable Credential")
public class IssueIdentityVCRequestDto {
    private String did;
    private String credentialType;
    private List<SupportingDocument> supportingDocuments;
}
