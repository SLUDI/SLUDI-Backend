package org.example.repository;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.example.entity.PermissionTemplate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PermissionTemplateRepository extends JpaRepository<PermissionTemplate, Long> {
    /*
    * Find all active templates
    * */
    List<PermissionTemplate> findByIsActive(Boolean isActive);

    // check existence of the template
    boolean existsByTemplateCode(@NotBlank(message = "Template code is required") @Pattern(regexp = "^[A-Z_]+$", message = "Template code must contain only uppercase letters and underscores") @Size(max = 50, message = "Template code must not exceed 50 characters") String templateCode);
}
