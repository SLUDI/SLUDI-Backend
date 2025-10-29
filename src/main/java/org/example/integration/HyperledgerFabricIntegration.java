package org.example.integration;

import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.TlsChannelCredentials;
import lombok.extern.slf4j.Slf4j;
import org.hyperledger.fabric.client.Contract;
import org.hyperledger.fabric.client.Gateway;
import org.hyperledger.fabric.client.identity.*;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Properties;
import java.util.Set;

@Slf4j
@Configuration
public class HyperledgerFabricIntegration {

    @Value("${fabric.msp-id}")
    private String mspId;

    @Value("${fabric.channel-name}")
    private String channelName;

    @Value("${fabric.chaincode-name}")
    private String chaincodeName;

    @Value("${fabric.crypto-path}")
    private String cryptoPath;

    @Value("${fabric.peer-endpoint}")
    private String peerEndpoint;

    @Value("${fabric.override-auth}")
    private String overrideAuth;

    @Value("${fabric.ca.url}")
    private String caUrl;

    @Value("${fabric.ca.admin.name}")
    private String caAdminName;

    @Value("${fabric.ca.admin.secret}")
    private String caAdminSecret;

    private Identity identity;
    private Signer signer;

    /**
     * Loads MSP identity certificate.
     */
    @Bean
    public Identity fabricIdentity() throws Exception {
        if (identity == null) {
            Path certPath = Paths.get(cryptoPath, "users/User1@org1.example.com/msp/signcerts");
            var certificate = Identities.readX509Certificate(
                    Files.newBufferedReader(getFirstFilePath(certPath))
            );
            identity = new X509Identity(mspId, certificate);
            log.info("Loaded Fabric identity for MSP: {}", mspId);
        }
        return identity;
    }

    /**
     * Loads signer private key.
     */
    @Bean
    public Signer fabricSigner() throws Exception {
        if (signer == null) {
            Path keyPath = Paths.get(cryptoPath, "users/User1@org1.example.com/msp/keystore");
            var privateKey = Identities.readPrivateKey(
                    Files.newBufferedReader(getPrivateKeyFile(keyPath))
            );
            signer = Signers.newPrivateKeySigner(privateKey);
            log.info("Loaded Fabric signer (private key).");
        }
        return signer;
    }

    /**
     * Connects to Fabric Gateway.
     */
    @Bean
    public Gateway gateway(Identity fabricIdentity, Signer fabricSigner) throws Exception {
        var tlsCert = Paths.get(cryptoPath, "peers/peer0.org1.example.com/tls/ca.crt");

        var creds = TlsChannelCredentials.newBuilder()
                .trustManager(tlsCert.toFile())
                .build();

        ManagedChannel channel = Grpc.newChannelBuilder(peerEndpoint, creds)
                .overrideAuthority(overrideAuth)
                .build();

        log.info("Fabric Gateway connected at peer endpoint: {}", peerEndpoint);

        return Gateway.newInstance()
                .identity(fabricIdentity)
                .signer(fabricSigner)
                .connection(channel)
                .connect();
    }

    /**
     * Provides Fabric Contract instance for chaincode interactions.
     */
    @Bean
    public Contract contract(Gateway gateway) {
        log.info("Contract bean initialized for chaincode: {}", chaincodeName);
        return gateway.getNetwork(channelName).getContract(chaincodeName);
    }

    /**
     * Provides Fabric CA Admin user for registration/enrollment actions.
     */
    @Bean
    public User fabricCaAdmin() {
        return new User() {
            @Override
            public String getName() {
                return caAdminName;
            }

            @Override
            public Set<String> getRoles() {
                return Collections.emptySet();
            }

            @Override
            public String getAccount() {
                return null;
            }

            @Override
            public String getAffiliation() {
                return "org1.department1";
            }

            @Override
            public Enrollment getEnrollment() {
                try {
                    Properties props = new Properties();
                    props.put("allowAllHostNames", "true");
                    HFCAClient caClient = HFCAClient.createNewInstance(caUrl, props);
                    caClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
                    Enrollment enrollment = caClient.enroll(caAdminName, caAdminSecret);
                    log.info("Enrolled Fabric CA admin '{}'", caAdminName);
                    return enrollment;
                } catch (Exception e) {
                    log.error("Failed to enroll Fabric CA admin: {}", e.getMessage());
                    throw new RuntimeException("Fabric CA admin enrollment failed", e);
                }
            }

            @Override
            public String getMspId() {
                return mspId;
            }
        };
    }

    private Path getPrivateKeyFile(Path keyDirPath) throws IOException {
        try (var files = Files.list(keyDirPath)) {
            return files.findFirst()
                    .orElseThrow(() -> new IOException("No private key found in " + keyDirPath));
        }
    }

    private Path getFirstFilePath(Path dir) throws IOException {
        try (var files = Files.list(dir)) {
            return files.findFirst()
                    .orElseThrow(() -> new IOException("No file found in " + dir));
        }
    }
}
