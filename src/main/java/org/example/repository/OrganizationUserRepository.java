package org.example.repository;

import org.example.entity.OrganizationUser;
import org.example.enums.UserStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface OrganizationUserRepository extends JpaRepository<OrganizationUser, Long> {

    /**
     * Find user by username
     */
    Optional<OrganizationUser> findByUsername(String username);

    /**
     * Find user by email
     */
    Optional<OrganizationUser> findByEmail(String email);

    /**
     * Find user by employee ID
     */
    Optional<OrganizationUser> findByEmployeeId(String employeeId);

    /**
     * Find user by Fabric user ID
     */
    Optional<OrganizationUser> findByFabricUserId(String fabricUserId);

    /**
     * Check if email exists
     */
    boolean existsByEmail(String email);

    /**
     * Check if username exists
     */
    boolean existsByUsername(String username);

    /**
     * Check if employee ID exists
     */
    boolean existsByEmployeeId(String employeeId);

    /**
     * Find all users of an organization
     */
    @Query("SELECT u FROM OrganizationUser u WHERE u.organization.id = :organizationId")
    List<OrganizationUser> findByOrganizationId(@Param("organizationId") Long organizationId);

    /**
     * Find users by organization and status
     */
    @Query("SELECT u FROM OrganizationUser u WHERE u.organization.id = :organizationId AND u.status = :status")
    List<OrganizationUser> findByOrganizationIdAndStatus(
            @Param("organizationId") Long organizationId,
            @Param("status") UserStatus status);

    /**
     * Find pending users for approval
     */
    List<OrganizationUser> findByStatus(UserStatus status);

    /**
     * Find users by role
     */
    @Query("SELECT u FROM OrganizationUser u WHERE u.assignedRole.id = :roleId")
    List<OrganizationUser> findByRoleId(@Param("roleId") Long roleId);

    /**
     * Find active users of an organization
     */
    @Query("SELECT u FROM OrganizationUser u WHERE u.organization.id = :organizationId " +
            "AND u.status = 'ACTIVE'")
    List<OrganizationUser> findActiveUsersByOrganizationId(@Param("organizationId") Long organizationId);

    /**
     * Find users enrolled on blockchain
     */
    @Query("SELECT u FROM OrganizationUser u WHERE u.isEnrolledOnBlockchain = true")
    List<OrganizationUser> findEnrolledUsers();

    /**
     * Find users by department within organization
     */
    @Query("SELECT u FROM OrganizationUser u WHERE u.organization.id = :organizationId " +
            "AND u.department = :department")
    List<OrganizationUser> findByOrganizationIdAndDepartment(
            @Param("organizationId") Long organizationId,
            @Param("department") String department);

    /**
     * Count users by organization
     */
    @Query("SELECT COUNT(u) FROM OrganizationUser u WHERE u.organization.id = :organizationId")
    long countByOrganizationId(@Param("organizationId") Long organizationId);

    /**
     * Count active users by organization
     */
    @Query("SELECT COUNT(u) FROM OrganizationUser u WHERE u.organization.id = :organizationId " +
            "AND u.status = 'ACTIVE'")
    long countActiveUsersByOrganizationId(@Param("organizationId") Long organizationId);

    /**
     * Search users by name or email
     */
    @Query("SELECT u FROM OrganizationUser u WHERE " +
            "(LOWER(u.firstName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
            "OR LOWER(u.lastName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
            "OR LOWER(u.email) LIKE LOWER(CONCAT('%', :searchTerm, '%'))) " +
            "AND u.organization.id = :organizationId")
    List<OrganizationUser> searchUsers(
            @Param("organizationId") Long organizationId,
            @Param("searchTerm") String searchTerm);
}
