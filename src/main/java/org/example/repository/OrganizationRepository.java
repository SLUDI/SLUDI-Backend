package org.example.repository;

import jakarta.validation.constraints.Size;
import org.example.entity.Organization;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OrganizationRepository extends JpaRepository<Organization, Long> {

    boolean existsByRegistrationNumber(@Size(max = 100, message = "Registration number must not exceed 100 characters") String registrationNumber);

    boolean existsByOrgCode(String orgCode);
}
