package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DocumentRetrievalResult {
    private byte[] documentData;
    private DocumentMetadata metadata;
    private boolean success;
}
