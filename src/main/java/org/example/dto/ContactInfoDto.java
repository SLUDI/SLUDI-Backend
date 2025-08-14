package org.example.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ContactInfoDto {
    private String email;
    private String phone;
}
