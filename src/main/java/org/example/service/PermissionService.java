package org.example.service;

import jakarta.transaction.Transactional;
import jakarta.validation.ValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.CreatePermissionTemplateRequest;
import org.example.dto.CreatePermissionTemplateResponse;
import org.example.entity.PermissionTemplate;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.PermissionTemplateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class PermissionService {
    @Autowired
    private final PermissionTemplateRepository templateRepository;

    public CreatePermissionTemplateResponse addPermissionTemplate(CreatePermissionTemplateRequest request){

        log.info("Creating permission template with code: {}", request.getTemplateCode());

        validateBusinessRules(request);

        // Create Permission Template entity
        PermissionTemplate permissionTemplate = buildPermissionTemplate(request);
        PermissionTemplate savedTemplate = templateRepository.save(permissionTemplate);

        log.info("Successfully created permission template with ID: {}", savedTemplate.getId());

        return toTemplateResponse(savedTemplate);
    }

    private void validateBusinessRules(CreatePermissionTemplateRequest request) {
        // Check uniqueness (database-dependent)
        if (templateRepository.existsByTemplateCode(request.getTemplateCode())) {
            log.warn("Template code already exists: {}", request.getTemplateCode());
            throw new SludiException(ErrorCodes.TEMPLATE_EXISTS_WITH_CODE, request.getTemplateCode());
        }

        // Validate role consistency (cross-field business logic)
        validateRolePermissions(request.getPredefinedRoles(), request.getBasePermissions());

    }


    /*
    * Get all active permission templates
    * */
    public List<CreatePermissionTemplateResponse> getAllActiveTemplates(){
        return templateRepository.findByIsActive(true).stream()
                .map(this::toTemplateResponse)
                .collect(Collectors.toList());
    }

    public PermissionTemplate getTemplateById(Long templateId){
        return templateRepository.findById(templateId)
                .orElseThrow(()-> new SludiException(ErrorCodes.TEMPLATE_NOT_FOUND, String.valueOf(templateId)));
    }

    private CreatePermissionTemplateResponse toTemplateResponse(PermissionTemplate template) {
        return CreatePermissionTemplateResponse.builder()
                .id(template.getId())
                .templateCode(template.getTemplateCode())
                .name(template.getName())
                .category(template.getCategory())
                .description(template.getDescription())
                .basePermissions(template.getBasePermissions())
                .predefinedRoles(template.getPredefinedRoles())
                .isActive(template.getIsActive())
                .createdAt(template.getCreatedAt())
                .updatedAt(template.getUpdatedAt())
                .build();
    }
    private PermissionTemplate buildPermissionTemplate(CreatePermissionTemplateRequest request) {
        return PermissionTemplate.builder()
                .templateCode(request.getTemplateCode())
                .name(request.getName())
                .category(request.getCategory())
                .description(request.getDescription())
                .basePermissions(request.getBasePermissions())
                .predefinedRoles(request.getPredefinedRoles())
                .isActive(true)
                .build();
    }


    private void validateRolePermissions(
            List<PermissionTemplate.PredefinedRole> roles,
            List<String> basePermissions
    ) {
        for (var role : roles) {
            // Check role uniqueness within template
            long duplicateCount = roles.stream()
                    .filter(r -> r.getRoleCode().equals(role.getRoleCode()))
                    .count();

            if (duplicateCount > 1) {
                throw new ValidationException(
                        "Duplicate role code found: " + role.getRoleCode()
                );
            }

            // Ensure role permissions are subset of base permissions
            if (role.getPermissions() != null && !role.getPermissions().isEmpty()) {
                List<String> invalidRolePermissions = role.getPermissions().stream()
                        .filter(permission -> !basePermissions.contains(permission))
                        .toList();

                if (!invalidRolePermissions.isEmpty()) {
                    throw new ValidationException(
                            "Role '" + role.getRoleCode() + "' has permissions not in base: "
                                    + String.join(", ", invalidRolePermissions)
                    );
                }
            }

            // Business rule: Admin roles must have all base permissions
            if (Boolean.TRUE.equals(role.getIsAdmin())) {
                if (role.getPermissions() == null ||
                        !new HashSet<>(role.getPermissions()).containsAll(basePermissions)) {
                    throw new ValidationException(
                            "Admin role '" + role.getRoleCode() + "' must have all base permissions"
                    );
                }
            }
        }
    }



}