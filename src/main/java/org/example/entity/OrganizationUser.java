package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.enums.UserStatus;
import org.example.enums.VerificationStatus;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;

@Entity
@Table(name = "organization_users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OrganizationUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    // Link to organization
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organization_id", nullable = false)
    private Organization organization;

    // User identification
    @Column(name = "employee_id", unique = true, nullable = false, length = 50)
    private String employeeId;

    @Column(name = "email", unique = true, nullable = false, length = 100)
    private String email;

    @Column(name = "username", unique = true, nullable = false, length = 50)
    private String username;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    // Personal information
    @Column(name = "first_name", nullable = false, length = 100)
    private String firstName;

    @Column(name = "last_name", nullable = false, length = 100)
    private String lastName;

    @Column(name = "phone", length = 20)
    private String phone;

    @Column(name = "did", length = 20)
    private String did;

    // Role and department
    @Column(name = "department", length = 100)
    private String department;

    @Column(name = "designation", length = 100)
    private String designation;

    @Column(name = "job_title", length = 100)
    private String jobTitle;

    // Assigned role from permission template
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "assigned_role_id")
    private OrganizationRole assignedRole;

    // Blockchain identity
    @Column(name = "fabric_user_id", unique = true)
    private String fabricUserId; // e.g., "police_officer_001"

    @Column(name = "fabric_enrollment_id")
    private String fabricEnrollmentId;

    @Column(name = "is_enrolled_on_blockchain")
    @Builder.Default
    private Boolean isEnrolledOnBlockchain = false;

    @Column(name = "enrollment_date")
    private LocalDateTime enrollmentDate;

    // Status and verification
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    @Builder.Default
    private UserStatus status = UserStatus.PENDING;

    @Enumerated(EnumType.STRING)
    @Column(name = "verification_status", length = 20)
    @Builder.Default
    private VerificationStatus verificationStatus = VerificationStatus.NOT_STARTED;

    // Approval workflow
    @Column(name = "created_by")
    private Long createdBy;

    @Column(name = "approved_by")
    private Long approvedBy;

    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    @Column(name = "suspended_by")
    private Long suspendedBy;

    @Column(name = "suspended_at")
    private LocalDateTime suspendedAt;

    @Column(name = "suspension_reason", columnDefinition = "TEXT")
    private String suspensionReason;

    // Metadata
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
        employeeId = generateEmployeeId();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    private String generateEmployeeId() {
        if (employeeId == null && organization != null) {
            return organization.getOrgCode() + "_EMP_" +
                    System.currentTimeMillis();
        }
        return employeeId;
    }
}