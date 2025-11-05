package org.example.repository;

import jakarta.validation.constraints.Size;
import org.example.entity.Organization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface OrganizationRepository extends JpaRepository<Organization, Long> {

    boolean existsByRegistrationNumber(@Size(max = 100, message = "Registration number must not exceed 100 characters") String registrationNumber);

    boolean existsByOrgCode(String orgCode);

    /**
     * Find organizations by template
     */
    @Query("SELECT o FROM Organization o WHERE o.template.id = :templateId")
    List<Organization> findByTemplateId(@Param("templateId") Long templateId);

    /**
     * Get organization with template details
     */
    @Query("SELECT o FROM Organization o LEFT JOIN FETCH o.template WHERE o.id = :id")
    Optional<Organization> findByIdWithTemplate(@Param("id") Long id);
}
