package org.example.service;

import lombok.extern.slf4j.Slf4j;
import org.example.entity.FabricOrgConfig;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.FabricOrgConfigRepository;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
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

    private final FabricOrgConfigRepository fabricOrgConfigRepository;

    // Cache for CA clients
    private final Map<String, HFCAClient> caClientCache = new ConcurrentHashMap<>();

    // Cache for admin users
    private final Map<String, User> adminUserCache = new ConcurrentHashMap<>();

    public FabricCAService(FabricOrgConfigRepository fabricOrgConfigRepository) {
        this.fabricOrgConfigRepository = fabricOrgConfigRepository;
    }

    @PostConstruct
    public void init() throws Exception {
        log.info("Initializing Fabric CA Service");

        // Initialize crypto suite
        CryptoSuite cryptoSuite = CryptoSuiteFactory.getDefault().getCryptoSuite();

        log.info("Fabric CA Service initialized successfully");
    }

    /**
     * Get Fabric config for MSP
     */
    private FabricOrgConfig getFabricConfig(String mspId) {
        FabricOrgConfig fabricOrgConfig = fabricOrgConfigRepository.findByMspId(mspId);
        if (fabricOrgConfig != null) {
            return fabricOrgConfig;
        } else {
            throw new SludiException(ErrorCodes.FABRIC_CONFIG_NOT_FOUND, mspId);
        }
    }

    /**
     * Get CA client for specific MSP
     */
    public HFCAClient getCaClient(String mspId) throws Exception {
        if (caClientCache.containsKey(mspId)) {
            return caClientCache.get(mspId);
        }

        FabricOrgConfig fabricConfig = getFabricConfig(mspId);
        String caUrl = "https://" + fabricConfig.getCaEndpoint();

        log.info("Creating CA client for MSP: {} at URL: {}", mspId, caUrl);

        Properties props = new Properties();
        props.put("pemFile", getCaCertPath(fabricConfig));
        props.put("allowAllHostNames", "true");

        HFCAClient caClient = HFCAClient.createNewInstance(caUrl, props);
        CryptoSuite cryptoSuite = CryptoSuiteFactory.getDefault().getCryptoSuite();
        caClient.setCryptoSuite(cryptoSuite);

        caClientCache.put(mspId, caClient);

        log.info("CA client created successfully for: {}", mspId);

        return caClient;
    }

    /**
     * Get admin user for specific MSP (Properly implemented User interface)
     * This method will enroll admin with CA if not already enrolled
     */
    public User getAdminUser(String mspId) throws Exception {
        if (adminUserCache.containsKey(mspId)) {
            return adminUserCache.get(mspId);
        }

        log.info("Loading admin user for MSP: {}", mspId);

        FabricOrgConfig fabricConfig = getFabricConfig(mspId);
        String orgShortName = mspId.replace("MSP", "").toLowerCase();

        // Try to load existing admin from filesystem first
        Path adminCertPath = getAdminCertPath(fabricConfig);
        Path adminKeyPath = getAdminKeyPath(fabricConfig);

        // Check if we need to enroll admin with CA
        // The filesystem admin might not have CA enrollment, so we enroll it
        try {
            log.info("Attempting to enroll admin with CA for MSP: {}", mspId);

            HFCAClient caClient = getCaClient(mspId);

            // Enroll admin with default credentials
            Enrollment adminEnrollment = caClient.enroll("admin", "adminpw");

            log.info("Admin enrolled successfully with CA");

            // Create admin user with CA enrollment
            AdminUser adminUser = new AdminUser(
                    "admin",
                    orgShortName + ".department1",
                    mspId,
                    adminEnrollment.getCert(),
                    adminEnrollment.getKey()
            );

            adminUserCache.put(mspId, adminUser);

            log.info("Admin user loaded successfully for: {} with affiliation: {}",
                    mspId, adminUser.getAffiliation());

            return adminUser;

        } catch (Exception e) {
            log.error("Failed to enroll admin with CA: {}", e.getMessage());

            // Fallback: try to use filesystem admin (might not work for registration)
            log.warn("Falling back to filesystem admin credentials (may not have CA authority)");

            String certificate = Files.readString(adminCertPath);
            PrivateKey privateKey = loadPrivateKey(adminKeyPath);

            AdminUser adminUser = new AdminUser(
                    "admin",
                    orgShortName + ".department1",
                    mspId,
                    certificate,
                    privateKey
            );

            adminUserCache.put(mspId, adminUser);
            return adminUser;
        }
    }

    /**
     * Concrete implementation of User interface for Admin
     */
    private static class AdminUser implements User {
        private final String name;
        private final String affiliation;
        private final String mspId;
        private final Enrollment enrollment;
        private final Set<String> roles;

        public AdminUser(String name, String affiliation, String mspId,
                         String certificate, PrivateKey privateKey) {
            this.name = name;
            this.affiliation = affiliation;
            this.mspId = mspId;
            this.roles = new HashSet<>(Arrays.asList("admin", "user"));

            // Create enrollment
            this.enrollment = new Enrollment() {
                @Override
                public PrivateKey getKey() {
                    return privateKey;
                }

                @Override
                public String getCert() {
                    return certificate;
                }
            };
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public Set<String> getRoles() {
            return roles;
        }

        @Override
        public String getAccount() {
            return name;
        }

        @Override
        public String getAffiliation() {
            return affiliation;
        }

        @Override
        public Enrollment getEnrollment() {
            return enrollment;
        }

        @Override
        public String getMspId() {
            return mspId;
        }

        @Override
        public String toString() {
            return String.format("AdminUser{name='%s', mspId='%s', affiliation='%s'}",
                    name, mspId, affiliation);
        }
    }

    /**
     * Store user enrollment in wallet
     */
    public void storeUserEnrollment(String mspId, String userId, Enrollment enrollment)
            throws Exception {
        log.info("Storing enrollment for user: {} in MSP: {}", userId, mspId);

        FabricOrgConfig fabricConfig = getFabricConfig(mspId);
        Path walletPath = Paths.get(fabricConfig.getWalletPath(), userId);
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

        log.info("Enrollment stored successfully in wallet at: {}", walletPath);
    }

    /**
     * Load user enrollment from wallet
     */
    public Enrollment loadUserEnrollment(String mspId, String userId) throws Exception {
        log.info("Loading enrollment for user: {} from MSP: {}", userId, mspId);

        FabricOrgConfig fabricConfig = getFabricConfig(mspId);
        Path walletPath = Paths.get(fabricConfig.getWalletPath(), userId);

        if (!Files.exists(walletPath)) {
            throw new FileNotFoundException("User enrollment not found in wallet: " + walletPath);
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

    private String getCaCertPath(FabricOrgConfig fabricConfig) {
        String orgName = extractOrgName(fabricConfig.getCryptoPath());
        return String.format("%s/ca/ca.%s-cert.pem",
                fabricConfig.getCryptoPath(), orgName);
    }

    private Path getAdminCertPath(FabricOrgConfig fabricConfig) throws IOException {
        String orgName = extractOrgName(fabricConfig.getCryptoPath());
        Path signcertsPath = Paths.get(
                fabricConfig.getCryptoPath(),
                "users", "Admin@" + orgName, "msp", "signcerts"
        );

        // Find first .pem file in signcerts directory
        return Files.list(signcertsPath)
                .filter(p -> p.toString().endsWith(".pem"))
                .findFirst()
                .orElseThrow(() -> new FileNotFoundException("Admin cert not found in: " + signcertsPath));
    }


    private Path getAdminKeyPath(FabricOrgConfig fabricConfig) throws IOException {
        String orgName = extractOrgName(fabricConfig.getCryptoPath());
        Path keystorePath = Paths.get(fabricConfig.getCryptoPath(),
                "users", "Admin@" + orgName, "msp", "keystore");

        // Find first key file in keystore directory
        return Files.list(keystorePath)
                .filter(p -> p.toString().endsWith("_sk"))
                .findFirst()
                .orElseThrow(() -> new FileNotFoundException("Admin key not found in: " + keystorePath));
    }

    /**
     * Extract organization name from crypto path
     * Example: /path/to/org1.example.com -> org1.example.com
     */
    private String extractOrgName(String cryptoPath) {
        Path path = Paths.get(cryptoPath);
        return path.getFileName().toString();
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

        // Remove PEM headers/footers and whitespace
        keyPem = keyPem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN EC PRIVATE KEY-----", "")
                .replace("-----END EC PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(keyPem);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC"); // Elliptic Curve

        return kf.generatePrivate(spec);
    }
}