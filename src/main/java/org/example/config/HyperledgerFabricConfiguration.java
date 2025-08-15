package org.example.config;

import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.TlsChannelCredentials;
import org.hyperledger.fabric.client.*;
import org.hyperledger.fabric.client.identity.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

@Configuration
public class HyperledgerFabricConfiguration {
    private static final Logger LOGGER = Logger.getLogger(HyperledgerFabricConfiguration.class.getName());

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

    @Bean
    public ManagedChannel grpcChannel() throws IOException {
        LOGGER.info("Creating gRPC channel for peer: " + peerEndpoint);
        Path tlsCertPath = Paths.get(cryptoPath, "peers/peer0.org1.example.com/tls/ca.crt");
        if (!Files.exists(tlsCertPath)) {
            throw new IOException("TLS certificate not found at: " + tlsCertPath);
        }
        var credentials = TlsChannelCredentials.newBuilder()
                .trustManager(tlsCertPath.toFile())
                .build();
        return Grpc.newChannelBuilder(peerEndpoint, credentials)
                .overrideAuthority(overrideAuth)
                .build();
    }

    @Bean
    public Identity identity() throws IOException, CertificateException {
        LOGGER.info("Loading identity from: " + cryptoPath);
        Path certDirPath = Paths.get(cryptoPath, "users/User1@org1.example.com/msp/signcerts");
        if (!Files.exists(certDirPath)) {
            throw new IOException("Certificate directory not found at: " + certDirPath);
        }
        try (var certReader = Files.newBufferedReader(getFirstFilePath(certDirPath))) {
            var certificate = Identities.readX509Certificate(certReader);
            return new X509Identity(mspId, certificate);
        }
    }

    @Bean
    public Signer signer() throws IOException, InvalidKeyException {
        LOGGER.info("Loading signer from: " + cryptoPath);
        Path keyDirPath = Paths.get(cryptoPath, "users/User1@org1.example.com/msp/keystore");
        if (!Files.exists(keyDirPath)) {
            throw new IOException("Private key directory not found at: " + keyDirPath);
        }
        try (var keyReader = Files.newBufferedReader(getFirstFilePath(keyDirPath))) {
            var privateKey = Identities.readPrivateKey(keyReader);
            return Signers.newPrivateKeySigner(privateKey);
        }
    }

    @Bean
    public Gateway gateway(ManagedChannel channel, Identity identity, Signer signer) {
        LOGGER.info("Creating Gateway with mspId: " + mspId);
        try {
            return Gateway.newInstance()
                    .identity(identity)
                    .signer(signer)
                    .hash(Hash.SHA256)
                    .connection(channel)
                    .evaluateOptions(options -> options.withDeadlineAfter(5, TimeUnit.SECONDS))
                    .endorseOptions(options -> options.withDeadlineAfter(15, TimeUnit.SECONDS))
                    .submitOptions(options -> options.withDeadlineAfter(5, TimeUnit.SECONDS))
                    .commitStatusOptions(options -> options.withDeadlineAfter(1, TimeUnit.MINUTES))
                    .connect();
        } catch (Exception e) {
            LOGGER.severe("Failed to create Gateway: " + e.getMessage());
            throw new RuntimeException("Gateway creation failed", e);
        }
    }

    @Bean
    public Contract contract(Gateway gateway) {
        LOGGER.info("Creating Contract for chaincode: " + chaincodeName + " on channel: " + channelName);
        var network = gateway.getNetwork(channelName);
        return network.getContract(chaincodeName);
    }

    private Path getFirstFilePath(Path dirPath) throws IOException {
        try (var keyFiles = Files.list(dirPath)) {
            return keyFiles.findFirst().orElseThrow(() -> new IOException("No files found in directory: " + dirPath));
        }
    }
}
