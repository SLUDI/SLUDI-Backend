package org.example.dto;

import lombok.*;
import org.example.entity.PermissionTemplate;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PermissionTemplateResponse {

    private Long id;
    private String templateCode;
    private String name;
    private PermissionTemplate.TemplateCategory category;
    private String description;
    private List<String> basePermissions;
    private List<PermissionTemplate.PredefinedRole> predefinedRoles;
    private Boolean isActive;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}

