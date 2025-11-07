package org.example.repository;

import org.example.entity.OrganizationOnboarding;
import org.example.enums.OnboardingStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OrganizationOnboardingRepository extends JpaRepository<OrganizationOnboarding, Long> {

    /**
     * Find onboarding record by organization ID
     */
    Optional<OrganizationOnboarding> findByOrganizationId(Long organizationId);

    /**
     * Find onboarding record by MSP ID
     */
    Optional<OrganizationOnboarding> findByMspId(String mspId);

    /**
     * Get all assigned MSP IDs (to find available Fabric orgs)
     */
    @Query("SELECT o.mspId FROM OrganizationOnboarding o WHERE o.mspId IS NOT NULL")
    List<String> findAllAssignedMspIds();

    /**
     * Get all onboarding records with organization details
     */
    @Query("SELECT o FROM OrganizationOnboarding o JOIN FETCH o.organization")
    List<OrganizationOnboarding> findAllWithOrganization();

    /**
     * Find by onboarding status
     */
    List<OrganizationOnboarding> findByOnboardingStatus(OnboardingStatus status);

    /**
     * Check if MSP ID is already assigned
     */
    boolean existsByMspId(String mspId);

    /**
     * Count assigned Fabric organizations
     */
    @Query("SELECT COUNT(o) FROM OrganizationOnboarding o WHERE o.mspId IS NOT NULL")
    long countAssignedOrganizations();
}
