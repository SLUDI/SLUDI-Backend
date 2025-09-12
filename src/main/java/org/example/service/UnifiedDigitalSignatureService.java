package org.example.service;

import jakarta.annotation.PostConstruct;

import org.hyperledger.fabric.client.identity.Signer;
import org.example.exception.ErrorCodes;
import org.hyperledger.fabric.client.identity.Identity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.example.exception.SludiException;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * Unified Digital Signature Service that integrates with Hyperledger Fabric
 * Uses the same Admin identity for both Fabric operations and DID document signing
 */
@Service
public class UnifiedDigitalSignatureService {

    private static final Logger LOGGER = Logger.getLogger(UnifiedDigitalSignatureService.class.getName());

    @Value("${sludi.organization.msp-id}")
    private String mspId;

    @Value("${sludi.issuer-did}")
    private String issuerDid;

    @Value("${sludi.signature.proof-type:RsaSignature2018}")
    private String proofType;

    @Value("${sludi.security.signature.audit.enabled:true}")
    private boolean auditEnabled;

    // Inject Fabric components
    @Autowired
    private Signer fabricSigner;

    @Autowired
    private Identity fabricIdentity;

    // For direct cryptographic operations (extracted from Fabric identity)
    private PrivateKey organizationPrivateKey;
    private X509Certificate organizationCertificate;

    @PostConstruct
    public void initializeFromFabricIdentity() {
        try {
            LOGGER.info("Initializing unified signature service with Fabric identity for MSP: " + mspId);

            // Extract certificate from Fabric Identity
            if (fabricIdentity instanceof org.hyperledger.fabric.client.identity.X509Identity) {
                org.hyperledger.fabric.client.identity.X509Identity x509Identity =
                        (org.hyperledger.fabric.client.identity.X509Identity) fabricIdentity;
                this.organizationCertificate = x509Identity.getCertificate();

                LOGGER.info("Successfully extracted certificate from Fabric identity");
                LOGGER.info("Certificate Subject: " + organizationCertificate.getSubjectX500Principal().getName());
            } else {
                throw new IllegalStateException("Fabric identity is not X509Identity type");
            }

        } catch (Exception e) {
            LOGGER.severe("Failed to initialize unified signature service: " + e.getMessage());
            throw new SludiException(ErrorCodes.CRYPTO_INITIALIZATION_FAILED, e.getMessage());
        }
    }

    /**
     * Signs DID document data using Fabric's signing mechanism
     * This ensures consistency with Fabric's transaction signing
     */
    public String signDIDDocument(String nic, String didId, String timestamp) {
        try {
            // Create the data to be signed
            String dataToSign = createCanonicalSignatureInput(nic, didId, timestamp);
            byte[] dataBytes = dataToSign.getBytes(StandardCharsets.UTF_8);

            // Use Fabric's signer to sign the data
            byte[] signatureBytes = fabricSigner.sign(dataBytes);
            String signatureValue = Base64.getEncoder().encodeToString(signatureBytes);

            // Audit logging if enabled
            if (auditEnabled) {
                LOGGER.info("DID_SIGNATURE_CREATED: DID=" + didId +
                        ", MSP=" + mspId +
                        ", Timestamp=" + timestamp +
                        ", DataToSign=" + dataToSign);
            }

            return signatureValue;

        } catch (Exception e) {
            LOGGER.severe("Failed to sign DID document for DID " + didId + ": " + e.getMessage());
            throw new SludiException(ErrorCodes.SIGNATURE_CREATION_FAILED, e);
        }
    }

    /**
     * Creates canonical representation of data to be signed
     */
    private String createCanonicalSignatureInput(String nic, String didId, String timestamp) {
        // Include MSP ID and issuer DID for organization identification
        return String.format("msp=%s&issuer=%s&nic=%s&did=%s&timestamp=%s&purpose=DIDCreation",
                mspId, issuerDid, nic, didId, timestamp);
    }

    /**
     * Verify that the service is properly initialized
     */
    public boolean isInitialized() {
        return fabricSigner != null &&
                fabricIdentity != null &&
                organizationCertificate != null &&
                mspId != null &&
                issuerDid != null;
    }
}