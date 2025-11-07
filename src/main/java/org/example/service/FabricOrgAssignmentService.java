package org.example.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.entity.FabricOrgConfig;
import org.example.entity.Organization;
import org.example.entity.OrganizationOnboarding;
import org.example.enums.OnboardingStatus;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.FabricOrgConfigRepository;
import org.example.repository.OrganizationOnboardingRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class FabricOrgAssignmentService {

    private final FabricOrgConfigRepository fabricConfigRepository;
    private final OrganizationOnboardingRepository onboardingRepository;

    /**
     * Assign available Fabric organization to the newly approved organization
     */
    @Transactional
    public OrganizationOnboarding assignFabricOrganization(Organization organization) {
        log.info("Assigning Fabric organization to: {}", organization.getOrgCode());

        FabricOrgConfig availableFabricOrg = findAvailableFabricOrg();

        if (availableFabricOrg == null) {
            throw new SludiException(ErrorCodes.NO_FABRIC_ORG_AVAILABLE);
        }

        // Create onboarding record
        OrganizationOnboarding onboarding = OrganizationOnboarding.builder()
                .organization(organization)
                .mspId(availableFabricOrg.getMspId())
                .peerEndpoint(availableFabricOrg.getPeerEndpoint())
                .caEndpoint(availableFabricOrg.getCaEndpoint())
                .ordererEndpoint(availableFabricOrg.getOrdererEndpoint())
                .cryptoConfigPath(availableFabricOrg.getCryptoPath())
                .onboardingStatus(OnboardingStatus.INITIATED)
                .build();

        onboarding = onboardingRepository.save(onboarding);

        log.info("Fabric organization assigned: {} -> {}",
                organization.getOrgCode(),
                availableFabricOrg.getMspId());

        return onboarding;
    }

    /**
     * Find next available Fabric organization (not yet assigned)
     */
    private FabricOrgConfig findAvailableFabricOrg() {
        // Get all Fabric configs
        List<FabricOrgConfig> allFabricOrgs = fabricConfigRepository.findByIsAssignedFalse();

        // Find first unassigned Fabric org
        return allFabricOrgs.stream()
                .findFirst()
                .orElse(null);
    }

}
