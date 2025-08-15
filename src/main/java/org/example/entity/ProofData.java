package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Embeddable
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProofData {

    private String type;
    private String created;
    private String verificationMethod;

    @Column(name = "proof_signature", length = 2000)
    private String proofValue;
    private String proofPurpose;
    private String challenge;
    private String domain;
}
