package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerifiablePresentationDto {
    private String context; // "@context": ["https://www.w3.org/2018/credentials/v1"]
    private String type; // "VerifiablePresentation"
    private String holder; // Citizen's DID
    private String credentialId;
    private Map<String, Object> attributes; // User given attributes
    private VPProofDto proof; // Proof of DID ownership
}
