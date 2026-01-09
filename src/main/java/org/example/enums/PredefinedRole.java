package org.example.enums;

import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
public enum PredefinedRole {
    ADMIN("ADMIN", "System Administrator", true),
    MANAGER("MANAGER", "Organization Manager", false),
    USER("USER", "Regular User", false),
    VIEWER("VIEWER", "Read-only User", false);

    private final String roleCode;
    private final String description;
    private final boolean isAdmin;

    PredefinedRole(String roleCode, String description, boolean isAdmin) {
        this.roleCode = roleCode;
        this.description = description;
        this.isAdmin = isAdmin;
    }

    public boolean getIsAdmin() {
        return isAdmin;
    }

    /**
     * Get default permissions for this role type
     * These are fallback permissions if no custom permissions are provided
     */
    public Set<String> getDefaultPermissions() {
        return switch (this) {
            case ADMIN -> Set.of("READ", "WRITE", "DELETE", "MANAGE_USERS", "MANAGE_ROLES");
            case MANAGER -> Set.of("READ", "WRITE", "MANAGE_USERS");
            case USER -> Set.of("READ", "WRITE");
            case VIEWER -> Set.of("READ");
        };
    }

    /**
     * Create a role instance with custom permissions based on template's base
     * permissions
     * This allows flexibility while maintaining the role type
     */
    public RoleInstance withPermissions(List<String> permissions) {
        return new RoleInstance(this.roleCode, this.description, this.isAdmin, permissions);
    }

    /**
     * Create a role instance with all permissions from the provided base
     * permissions
     * Useful for ADMIN roles that should get all available permissions
     */
    public RoleInstance withAllPermissions(List<String> basePermissions) {
        return new RoleInstance(this.roleCode, this.description, this.isAdmin, basePermissions);
    }

    /**
     * Create a role instance with filtered permissions based on base permissions
     * Only includes permissions that exist in both default and base permissions
     */
    public RoleInstance withFilteredPermissions(List<String> basePermissions) {
        Set<String> defaultPerms = getDefaultPermissions();
        List<String> filtered = basePermissions.stream()
                .filter(defaultPerms::contains)
                .collect(Collectors.toList());
        return new RoleInstance(this.roleCode, this.description, this.isAdmin, filtered);
    }

    /**
     * Inner class to represent a role instance with custom permissions
     */
    @Getter
    @NoArgsConstructor
    public static class RoleInstance {
        private String roleCode;
        private String description;
        private boolean isAdmin;
        private List<String> permissions;

        public RoleInstance(String roleCode, String description, boolean isAdmin, List<String> permissions) {
            this.roleCode = roleCode;
            this.description = description;
            this.isAdmin = isAdmin;
            this.permissions = new ArrayList<>(permissions);
        }

        public boolean getIsAdmin() {
            return isAdmin;
        }
    }
}