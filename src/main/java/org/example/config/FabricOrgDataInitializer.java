package org.example.config;

import lombok.extern.slf4j.Slf4j;
import org.example.entity.FabricOrgConfig;
import org.example.repository.FabricOrgConfigRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@Slf4j
public class FabricOrgDataInitializer {

    @Bean
    public CommandLineRunner initFabricConfigs(FabricOrgConfigRepository repository) {
        return args -> {

            if (!repository.existsByMspId("Org1MSP")) {
                FabricOrgConfig org1 = FabricOrgConfig.builder()
                        .mspId("Org1MSP")
                        .channelName("sludi-channel")
                        .chainCodeName("sludi-Chaincode")
                        .cryptoPath("/home/tishan/development/go/src/github.com/tishan/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com")
                        .peerEndpoint("localhost:7051")
                        .ordererEndpoint("localhost:7050")
                        .caEndpoint("localhost:7054")
                        .walletPath("/home/tishan/development/go/src/github.com/tishan/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/msp/keystore")
                        .isAssigned(false)
                        .build();

                repository.save(org1);
            }

            if (!repository.existsByMspId("Org2MSP")) {
                FabricOrgConfig org2 = FabricOrgConfig.builder()
                        .mspId("Org2MSP")
                        .channelName("sludi-channel")
                        .chainCodeName("sludi-Chaincode")
                        .cryptoPath("/home/tishan/development/go/src/github.com/tishan/fabric-samples/test-network/organizations/peerOrganizations/org2.example.com")
                        .peerEndpoint("localhost:9051")
                        .ordererEndpoint("localhost:7050")
                        .caEndpoint("localhost:8054")
                        .walletPath("/home/tishan/development/go/src/github.com/tishan/fabric-samples/test-network/organizations/peerOrganizations/org2.example.com/msp/keystore")
                        .isAssigned(false)
                        .build();

                repository.save(org2);
            }

            log.info("Default FabricOrgConfig rows initialized successfully.");
        };
    }
}
