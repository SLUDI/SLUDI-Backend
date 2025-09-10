package org.example.dto;

import lombok.Builder;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
@Builder
public class SupportingDocument {
    private String name;
    private String type;
    private MultipartFile file;
}
