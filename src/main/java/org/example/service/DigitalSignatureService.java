package org.example.service;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.example.entity.ProofData;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.hyperledger.fabric.client.identity.Identity;
import org.hyperledger.fabric.client.identity.Signer;
import org.hyperledger.fabric.client.identity.X509Identity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Objects;

/**
 * DigitalSignatureService
 *
 * Unified Digital Signature Service that integrates with Hyperledger Fabric.
 * It uses the same admin identity for both Fabric transaction signing
 * and document signing.
 *
 * Responsibilities:
 *  - Initialize from Fabric identity (certificate extraction)
 *  - Create proof data (W3C-style signature metadata + signature)
 *  - Sign arbitrary data using Fabric’s signer
 */
@Slf4j
@Service
public class DigitalSignatureService {

    @Value("${sludi.organization.msp-id}")
    private String mspId;

    @Value("${sludi.issuer-did}")
    private String issuerDid;

    @Value("${sludi.signature.proof-type:RsaSignature2018}")
    private String proofType;

    @Value("${sludi.security.signature.audit.enabled:true}")
    private boolean auditEnabled;

    @Autowired
    private Signer fabricSigner;

    @Autowired
    private Identity fabricIdentity;

    // Certificate extracted from Fabric identity
    private X509Certificate organizationCertificate;

    /**
     * Initializes service from Fabric Identity.
     * Ensures that the certificate is extracted successfully
     * for organizational-level identification.
     */
    @PostConstruct
    public void initializeFromFabricIdentity() {
        try {
            log.info("Initializing DigitalSignatureService with Fabric identity [MSP={}]", mspId);

            if (fabricIdentity instanceof X509Identity x509Identity) {
                this.organizationCertificate = x509Identity.getCertificate();

                log.info("Successfully extracted certificate. Subject: {}",
                        organizationCertificate.getSubjectX500Principal().getName()
                );
            } else {
                throw new IllegalStateException("Fabric identity is not of type X509Identity");
            }

        } catch (Exception e) {
            log.error("Failed to initialize DigitalSignatureService: {}", e.getMessage());
            throw new SludiException(ErrorCodes.CRYPTO_INITIALIZATION_FAILED, e.getMessage(), e);
        }
    }

    /**
     * Creates a ProofDataDto for given input.
     *
     * @param data      Business/identity data being signed
     * @param id        Unique identifier (e.g., DID, CredentialID)
     * @param timestamp Timestamp when the proof is created
     * @param purpose   Proof purpose (e.g., "DIDCreation")
     * @return ProofDataDto containing signature and metadata
     */
    public ProofData createProofData(String data, String id, String timestamp, String purpose) {
        try {
            validateInputs(data, id, purpose);

            String signatureValue = signDocument(data, id, timestamp, purpose);

            log.info("ProofData created for ID={}, Issuer={}, Timestamp={}", id, issuerDid, timestamp);

            return ProofData.builder()
                    .proofType(proofType)
                    .created(timestamp)
                    .creator(issuerDid + "#key-1") // TODO: externalize key reference
                    .issuerDid(issuerDid)
                    .signatureValue(signatureValue)
                    .build();

        } catch (Exception e) {
            log.error(
                    "Failed to create ProofData for ID {}: {}", id, e.getMessage());
            throw new SludiException(ErrorCodes.SIGNATURE_CREATION_FAILED, e.getMessage(), e);
        }
    }

    /**
     * Signs the canonical input data using Fabric's signer.
     *
     * @param data      Business/identity data being signed
     * @param id        Identifier (e.g., DID, CredentialID)
     * @param timestamp Timestamp string
     * @param purpose   Purpose of signature
     * @return Base64-encoded digital signature
     */
    private String signDocument(String data, String id, String timestamp, String purpose) {
        try {
            String dataToSign = createCanonicalSignatureInput(data, id, timestamp, purpose);
            byte[] signatureBytes = fabricSigner.sign(dataToSign.getBytes(StandardCharsets.UTF_8));
            String signatureValue = Base64.getEncoder().encodeToString(signatureBytes);

            if (auditEnabled) {
                // Keep audit logs lightweight (avoid logging raw signature)
                log.info("SIGNATURE_CREATED [ID={}, MSP={}, Timestamp={}]",
                                id, mspId, timestamp);
            }

            return signatureValue;

        } catch (Exception e) {
            log.error(
                    "Failed to sign document for ID {}: {}", id, e.getMessage());
            throw new SludiException(ErrorCodes.SIGNATURE_CREATION_FAILED, e.getMessage(), e);
        }
    }

    /**
     * Creates a canonical representation of the data before signing.
     * This ensures deterministic input for signatures.
     */
    private String createCanonicalSignatureInput(String data, String id, String timestamp, String purpose) {
        return String.format(
                "msp=%s&issuer=%s&nic=%s&did=%s&timestamp=%s&purpose=%s",
                mspId, issuerDid, data, id, timestamp, purpose
        );
    }

    /**
     * Service health check to confirm initialization success.
     */
    public boolean isInitialized() {
        return fabricSigner != null &&
                fabricIdentity != null &&
                organizationCertificate != null &&
                mspId != null &&
                issuerDid != null;
    }

    /**
     * Validates inputs to avoid null or incomplete proof requests.
     */
    private void validateInputs(String data, String id, String purpose) {
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(id, "ID cannot be null");
        Objects.requireNonNull(purpose, "Purpose cannot be null");
    }
}
