package org.example.service;

import lombok.extern.slf4j.Slf4j;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class FabricCAService {

    @Value("${fabric.wallet.path:./wallet}")
    private String walletBasePath;

    @Value("${fabric.network.path:./fabric-network}")
    private String networkPath;

    // Cache for CA clients
    private final Map<String, HFCAClient> caClientCache = new ConcurrentHashMap<>();

    // Cache for admin users
    private final Map<String, User> adminUserCache = new ConcurrentHashMap<>();

    // CA endpoints configuration
    private final Map<String, String> caEndpoints = new HashMap<>();

    @PostConstruct
    public void init() throws Exception {
        log.info("Initializing Fabric CA Service");

        // Configure CA endpoints for each organization
        caEndpoints.put("Org1MSP", "https://localhost:7054");
        caEndpoints.put("Org2MSP", "https://localhost:8054");
        caEndpoints.put("Org3MSP", "https://localhost:9054");
        caEndpoints.put("Org4MSP", "https://localhost:10054");

        // Initialize crypto suite
        CryptoSuite cryptoSuite = CryptoSuiteFactory.getDefault().getCryptoSuite();

        log.info("Fabric CA Service initialized successfully");
    }

    /**
     * Get CA client for specific MSP
     */
    public HFCAClient getCaClient(String mspId) throws Exception {
        if (caClientCache.containsKey(mspId)) {
            return caClientCache.get(mspId);
        }

        String caUrl = caEndpoints.get(mspId);
        if (caUrl == null) {
            throw new IllegalArgumentException("Unknown MSP ID: " + mspId);
        }

        log.info("Creating CA client for MSP: {} at URL: {}", mspId, caUrl);

        Properties props = new Properties();
        props.put("pemFile", getCaCertPath(mspId));
        props.put("allowAllHostNames", "true");

        HFCAClient caClient = HFCAClient.createNewInstance(caUrl, props);
        CryptoSuite cryptoSuite = CryptoSuiteFactory.getDefault().getCryptoSuite();
        caClient.setCryptoSuite(cryptoSuite);

        caClientCache.put(mspId, caClient);

        log.info("CA client created successfully for: {}", mspId);

        return caClient;
    }

    /**
     * Get admin user for specific MSP
     */
    public User getAdminUser(String mspId) throws Exception {
        if (adminUserCache.containsKey(mspId)) {
            return adminUserCache.get(mspId);
        }

        log.info("Loading admin user for MSP: {}", mspId);

        // Load admin enrollment from filesystem
        Path adminCertPath = getAdminCertPath(mspId);
        Path adminKeyPath = getAdminKeyPath(mspId);

        X509Certificate certificate = loadCertificate(adminCertPath);
        PrivateKey privateKey = loadPrivateKey(adminKeyPath);

        // Create enrollment
        Enrollment enrollment = new Enrollment() {
            @Override
            public PrivateKey getKey() {
                return privateKey;
            }

            @Override
            public String getCert() {
                try {
                    return new String(Files.readAllBytes(adminCertPath));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };

        // Create admin user
        User adminUser = new User() {
            @Override
            public String getName() {
                return "admin";
            }

            @Override
            public Set<String> getRoles() {
                return new HashSet<>(Arrays.asList("admin"));
            }

            @Override
            public String getAccount() {
                return "admin";
            }

            @Override
            public String getAffiliation() {
                return "org1.department1";
            }

            @Override
            public Enrollment getEnrollment() {
                return enrollment;
            }

            @Override
            public String getMspId() {
                return mspId;
            }
        };

        adminUserCache.put(mspId, adminUser);

        log.info("Admin user loaded successfully for: {}", mspId);

        return adminUser;
    }

    /**
     * Store user enrollment in wallet
     */
    public void storeUserEnrollment(String mspId, String userId, Enrollment enrollment)
            throws Exception {
        log.info("Storing enrollment for user: {} in MSP: {}", userId, mspId);

        Path walletPath = Paths.get(walletBasePath, mspId, userId);
        Files.createDirectories(walletPath);

        // Store certificate
        Path certPath = walletPath.resolve("cert.pem");
        Files.writeString(certPath, enrollment.getCert());

        // Store private key
        Path keyPath = walletPath.resolve("key.pem");
        byte[] keyBytes = enrollment.getKey().getEncoded();
        String keyPem = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(keyBytes) +
                "\n-----END PRIVATE KEY-----\n";
        Files.writeString(keyPath, keyPem);

        log.info("Enrollment stored successfully in wallet");
    }

    /**
     * Load user enrollment from wallet
     */
    public Enrollment loadUserEnrollment(String mspId, String userId) throws Exception {
        log.info("Loading enrollment for user: {} from MSP: {}", userId, mspId);

        Path walletPath = Paths.get(walletBasePath, mspId, userId);

        if (!Files.exists(walletPath)) {
            throw new FileNotFoundException("User enrollment not found in wallet");
        }

        Path certPath = walletPath.resolve("cert.pem");
        Path keyPath = walletPath.resolve("key.pem");

        String cert = Files.readString(certPath);
        PrivateKey privateKey = loadPrivateKey(keyPath);

        return new Enrollment() {
            @Override
            public PrivateKey getKey() {
                return privateKey;
            }

            @Override
            public String getCert() {
                return cert;
            }
        };
    }

    // Helper methods for file paths

    private String getCaCertPath(String mspId) {
        String orgName = mspIdToOrgName(mspId);
        return String.format("%s/organizations/peerOrganizations/%s/ca/ca.%s-cert.pem",
                networkPath, orgName, orgName);
    }

    private Path getAdminCertPath(String mspId) {
        String orgName = mspIdToOrgName(mspId);
        return Paths.get(networkPath, "organizations", "peerOrganizations", orgName,
                "users", "Admin@" + orgName, "msp", "signcerts",
                "Admin@" + orgName + "-cert.pem");
    }

    private Path getAdminKeyPath(String mspId) throws IOException {
        String orgName = mspIdToOrgName(mspId);
        Path keystorePath = Paths.get(networkPath, "organizations", "peerOrganizations",
                orgName, "users", "Admin@" + orgName, "msp", "keystore");

        // Find first key file in keystore directory
        return Files.list(keystorePath)
                .filter(p -> p.toString().endsWith("_sk"))
                .findFirst()
                .orElseThrow(() -> new FileNotFoundException("Admin key not found"));
    }

    private String mspIdToOrgName(String mspId) {
        // Org1MSP -> org1.example.com
        String orgNum = mspId.replace("MSP", "").toLowerCase();
        return orgNum + ".example.com";
    }

    // Crypto utilities

    private X509Certificate loadCertificate(Path certPath) throws Exception {
        try (InputStream is = Files.newInputStream(certPath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(is);
        }
    }

    private PrivateKey loadPrivateKey(Path keyPath) throws Exception {
        String keyPem = Files.readString(keyPath);

        // Remove PEM headers/footers
        keyPem = keyPem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(keyPem);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC"); // Elliptic Curve

        return kf.generatePrivate(spec);
    }
}
