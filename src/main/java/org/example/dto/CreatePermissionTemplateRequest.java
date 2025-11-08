package org.example.dto;

import jakarta.validation.constraints.*;
import lombok.*;
import org.example.entity.PermissionTemplate;
import org.example.enums.PredefinedRole;
import org.example.enums.TemplateCategory;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CreatePermissionTemplateRequest {

    @NotBlank(message = "Template code is required")
    @Pattern(regexp = "^[A-Z_]+$", message = "Template code must contain only uppercase letters and underscores")
    @Size(max = 50, message = "Template code must not exceed 50 characters")
    private String templateCode;

    @NotBlank(message = "Template name is required")
    @Size(max = 100, message = "Template name must not exceed 100 characters")
    private String name;

    @NotNull(message = "Category is required")
    private TemplateCategory category;

    private String description;

    @NotEmpty(message = "Base permissions are required")
    private List<@Pattern(regexp = "^[a-z_]+:[a-z_:]+$",
            message = "Invalid permission format") String> basePermissions;

    @NotEmpty(message = "At least one predefined role is required")
    private List<PredefinedRole.RoleInstance> predefinedRoles;
}




