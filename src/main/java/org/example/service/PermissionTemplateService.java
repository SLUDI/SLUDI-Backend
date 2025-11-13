package org.example.service;

import jakarta.validation.ValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.CreatePermissionTemplateRequest;
import org.example.dto.PermissionTemplateResponse;
import org.example.dto.CustomPermissionsRequest;
import org.example.entity.Organization;
import org.example.entity.PermissionTemplate;
import org.example.enums.PredefinedRole;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.PermissionTemplateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class PermissionTemplateService {
    @Autowired
    private final PermissionTemplateRepository templateRepository;

    public PermissionTemplateResponse addPermissionTemplate(CreatePermissionTemplateRequest request){

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
    public List<PermissionTemplateResponse> getAllActiveTemplates(){
        return templateRepository.findByIsActive(true).stream()
                .map(this::toTemplateResponse)
                .collect(Collectors.toList());
    }

    public PermissionTemplate getTemplateById(Long templateId){
        return templateRepository.findById(templateId)
                .orElseThrow(()-> new SludiException(ErrorCodes.TEMPLATE_NOT_FOUND, String.valueOf(templateId)));
    }

    public void validateCustomPermissionsRequest(CustomPermissionsRequest request, Organization organization){
        if(request.getAdded() != null && !request.getAdded().isEmpty()){
            validatePermissions(request.getAdded());
        }

        if(request.getRemoved() != null && !request.getRemoved().isEmpty()){
            validatePermissions(request.getRemoved());

            // Check if the removed permissions available in the base permission list
            Set<String> basePermissions = new HashSet<>(
                    organization.getTemplate().getBasePermissions()
            );

            for( String permission : request.getRemoved()){
                if(!basePermissions.contains(permission)){
                    throw new SludiException(ErrorCodes.INVALID_PERMISSION, permission);
                }
            }

        }
    }
    /**
     * Calculate effective permissions for an organization
     * Formula: (base_permissions ∪ added) \ removed
     */
    public Set<String> calculateEffectivePermissions(Organization organization) {
        Set<String> effectivePermissions = new HashSet<>();

        // Start with base permissions from template
        if (organization.getTemplate() != null) {
            effectivePermissions.addAll(organization.getTemplate().getBasePermissions());
        }

        // Add custom added permissions
        if (organization.getCustomPermissions() != null) {
            if (organization.getCustomPermissions().getAdded() != null) {
                effectivePermissions.addAll(organization.getCustomPermissions().getAdded());
            }

            // Remove denied permissions
            if (organization.getCustomPermissions().getRemoved() != null) {
                    organization.getCustomPermissions().getRemoved().forEach(effectivePermissions::remove);
            }
        }

        return effectivePermissions;
    }

    // Helper Methods

    /**
     * Validate permissions against predefined list
     */
    public void validatePermissions(List<String> permissions){
        if( permissions == null || permissions.isEmpty()){
            return;
        }

        Set<String> validPermissions = getValidPermissionPatterns();

        for(String permission :permissions){
            if(!isValidFormat(permission)){
                throw new ValidationException("Invalid permission format :" + permission+
                        ". Must follow pattern: resource:action or resource:subresource:action"
                );
            }
            // Check if permission exists in valid list
            if(!validPermissions.contains(permission)&& !permission.endsWith("*")){
                log.warn("Permission not in predefined list: {}", permission);
            }
        }

    }

    private boolean isValidFormat(String permission){
        // Pattern: resource:action or resource:subresource:action or resource:*
        return permission.matches("^[a-z_]+:[a-z_*:]+$");
    }

    /**
     * Get all valid permission patterns (predefined list)
     */
    private Set<String> getValidPermissionPatterns(){
        return Set.of(
                // Organization management
                "organization:create", "organization:view", "organization:update",
                "organization:delete", "organization:approve", "organization:suspend",
                "organization:reactive",

                // Organization user management
                "organization:user:create", "organization:user:view", "organization:user:update",
                "organization:user:delete", "organization:user:approve", "organization:user:suspend",
                "organization:user:reactive",

                // Identity permissions
                "identity:read", "identity:verify", "identity:search", "identity:flag",
                "identity:history:read", "identity:kyc", "identity:kyc:update", "identity:kyc:approve",

                // Criminal records
                "criminal_records:read", "criminal_records:create", "criminal_records:update",

                // Warrants
                "warrant:read", "warrant:create",

                // Missing persons
                "missing_person:create", "missing_person:search", "missing_person:update",

                // Financial
                "financial_records:read", "financial_records:verify",
                "credit_check:perform", "credit_check:read",
                "account:verify", "account:link",
                "transaction:verify", "transaction:flag",

                // Licenses
                "license:read", "license:issue", "license:renew", "license:update",
                "license:revoke", "license:suspend", "license:history:read",

                // Vehicles
                "vehicle:read", "vehicle:register", "vehicle:update", "vehicle:transfer",
                "vehicle:history:read",

                // Violations and fines
                "violation:create", "violation:read", "violation:update",
                "fine:create", "fine:read", "fine:update",

                // Medical
                "medical_records:read", "medical_records:create", "medical_records:update",
                "medical_history:read",
                "prescription:create", "prescription:read", "prescription:update",
                "appointment:create", "appointment:read", "appointment:update",
                "lab_results:create", "lab_results:read",
                "insurance:verify", "insurance:claim",

                // Education
                "student_records:read", "student_records:create", "student_records:update",
                "academic_records:read", "academic_records:update",
                "enrollment:create", "enrollment:read", "enrollment:update",
                "certificate:issue", "certificate:verify",
                "transcript:generate", "transcript:verify",

                // Wildcards
                "identity:*", "criminal_records:*", "license:*", "vehicle:*",
                "medical_records:*", "student_records:*");
    }

    private PermissionTemplateResponse toTemplateResponse(PermissionTemplate template) {
        return PermissionTemplateResponse.builder()
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
            List<PredefinedRole.RoleInstance> roles,
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