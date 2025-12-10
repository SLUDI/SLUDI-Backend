package org.example.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonPropertyOrder({
        "proofType",
        "created",
        "creator",
        "issuerDid",
        "signatureValue"
})
public class ProofDataDto {
    private String proofType;
    private String created;
    private String creator;
    private String issuerDid;
    private String signatureValue;

    @JsonIgnore
    public boolean isValid() {
        return proofType != null && !proofType.isEmpty()
                && created != null && !created.isEmpty()
                && creator != null && !creator.isEmpty()
                && issuerDid != null && !issuerDid.isEmpty()
                && signatureValue != null && !signatureValue.isEmpty();
    }
}