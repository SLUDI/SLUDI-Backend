package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BiometricIPFSHashes {
    private String fingerprintHash;
    private String faceImageHash;
    private String signatureHash;
}
