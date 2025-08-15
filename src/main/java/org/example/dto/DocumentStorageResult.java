package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DocumentStorageResult {
    private String documentHash;
    private String metadataHash;
    private int fileSize;
    private boolean encrypted;
    private boolean success;
}
