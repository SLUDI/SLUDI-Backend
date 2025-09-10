package org.example.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@Schema(description = "Contact information")
public class ContactInfoDto {
    private String email;
    private String phone;
}
