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

    private String proofType;
    private String created;
    private String creator;

    @Column(name = "proof_signature", length = 2000)
    private String signatureValue;
}
