package org.example.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "permission_templates")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PermissionTemplate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "template_code", unique = true, nullable = false, length = 50)
    private String templateCode;

    @Column(name = "name", nullable = false, length = 100)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "category", nullable = false, length = 50)
    private TemplateCategory category;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "base_permissions", nullable = false, columnDefinition = "jsonb")
    private List<String> basePermissions;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "predefined_roles", nullable = false, columnDefinition = "jsonb")
    private List<PredefinedRole> predefinedRoles;

    @Column(name = "is_active")
    @Builder.Default
    private Boolean isActive = true;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public enum TemplateCategory {
        GOVERNMENT, FINANCIAL, HEALTHCARE, EDUCATION, CUSTOM
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class PredefinedRole {
        private String roleCode;
        private String roleName;
        private List<String> permissions;
        private Boolean isAdmin;
    }
}