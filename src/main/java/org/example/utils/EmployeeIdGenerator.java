package org.example.utils;

import lombok.RequiredArgsConstructor;
import org.example.entity.Organization;
import org.example.repository.OrganizationUserRepository;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class EmployeeIdGenerator {
    private final OrganizationUserRepository userRepository;
    
    public String generateCode(Organization org) {
        // Count existing users for that organization
        long count = userRepository.countByOrganizationId(org.getId());

        // Generate next sequential number
        long nextNumber = count + 1;
        String formatted = String.format("%03d", nextNumber);

        return org.getOrgCode() + "_EMP_" + formatted;
    }
}
