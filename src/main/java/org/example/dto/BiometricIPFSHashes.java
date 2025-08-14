package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class BiometricIPFSHashes {
    private String fingerprintHash;
    private String faceImageHash;
    private String signatureHash;
}
