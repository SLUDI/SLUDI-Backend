package org.example.repository;

import org.example.entity.OrganizationRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OrganizationRoleRepository extends JpaRepository<OrganizationRole, Long> {

    /**
     * Find all roles for an organization
     */
    @Query("SELECT r FROM OrganizationRole r JOIN FETCH r.organization WHERE r.organization.id = :organizationId")
    List<OrganizationRole> findByOrganizationId(@Param("organizationId") Long organizationId);

    /**
     * Find active roles for an organization
     */
    @Query("SELECT r FROM OrganizationRole r WHERE r.organization.id = :organizationId " +
            "AND r.isActive = true")
    List<OrganizationRole> findActiveRolesByOrganizationId(@Param("organizationId") Long organizationId);

    /**
     * Find role by code within organization
     */
    @Query("SELECT r FROM OrganizationRole r WHERE r.organization.id = :organizationId " +
            "AND r.roleCode = :roleCode")
    Optional<OrganizationRole> findByOrganizationIdAndRoleCode(
            @Param("organizationId") Long organizationId,
            @Param("roleCode") String roleCode);

    /**
     * Find admin roles for organization
     */
    @Query("SELECT r FROM OrganizationRole r WHERE r.organization.id = :organizationId " +
            "AND r.isAdmin = true")
    List<OrganizationRole> findAdminRolesByOrganizationId(@Param("organizationId") Long organizationId);

    /**
     * Check if roles exist for organization
     */
    @Query("SELECT CASE WHEN COUNT(r) > 0 THEN true ELSE false END " +
            "FROM OrganizationRole r WHERE r.organization.id = :organizationId")
    boolean existsByOrganizationId(@Param("organizationId") Long organizationId);

    /**
     * Count roles by organization
     */
    @Query("SELECT COUNT(r) FROM OrganizationRole r WHERE r.organization.id = :organizationId")
    long countByOrganizationId(@Param("organizationId") Long organizationId);

    /**
     * Find roles with specific permission
     */
    @Query(value = "SELECT r.* FROM organization_roles r " +
            "WHERE r.organization_id = :organizationId " +
            "AND r.permissions @> CAST(:permission AS jsonb)",
            nativeQuery = true)
    List<OrganizationRole> findByOrganizationIdAndPermission(
            @Param("organizationId") Long organizationId,
            @Param("permission") String permission);
}
