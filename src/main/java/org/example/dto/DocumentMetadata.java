package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DocumentMetadata {
    private String userId;
    private String documentType;
    private String fileName;
    private String mimeType;
    private int fileSize;
    private long uploadTimestamp;
    private boolean encrypted;
}