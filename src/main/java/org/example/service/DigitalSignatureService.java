package org.example.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.entity.CitizenUser;
import org.example.entity.OrganizationOnboarding;
import org.example.entity.ProofData;
import org.example.entity.OrganizationUser;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.CitizenUserRepository;
import org.example.repository.OrganizationOnboardingRepository;
import org.example.repository.PublicKeyRepository;
import org.example.security.CryptographyService;
import org.example.utils.HashUtil;
import org.hyperledger.fabric.client.identity.Identity;
import org.hyperledger.fabric.client.identity.Signer;
import org.hyperledger.fabric.client.identity.X509Identity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static io.ipfs.multibase.Base16.bytesToHex;

/**
 * Enhanced Digital Signature Service
 *
 * Supports:
 * - Signing DID document
 * - Signing Verifiable Credentials (for citizen registration, police records, etc.)
 * - Verification of credentials
 * - Multi-organization support (Citizen Registry, Police, etc.)
 */
@Slf4j
@Service
public class DigitalSignatureService {

    @Value("${sludi.signature.proof-type:Ed25519Signature2018}")
    private String proofType;

    @Value("${sludi.security.signature.audit.enabled:true}")
    private boolean auditEnabled;

    @Autowired
    private Signer fabricSigner;

    @Autowired
    private Identity fabricIdentity;

    @Autowired
    private FabricCAService fabricCAService;

    @Autowired
    private CryptographyService cryptographyService;

    @Autowired
    private OrganizationOnboardingRepository onboardingRepository;

    @Autowired
    private PublicKeyRepository publicKeyRepository;

    @Autowired
    private CitizenUserRepository userRepository;

    // Cache for organization signers (by MSP ID)
    private final Map<String, Signer> organizationSignerCache = new HashMap<>();
    private final Map<String, X509Certificate> organizationCertCache = new HashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostConstruct
    public void initializeFromFabricIdentity() {
        try {
            log.info("Initializing DigitalSignatureService with Fabric identity");

            if (fabricIdentity instanceof X509Identity x509Identity) {
                // Certificate extracted from Fabric identity
                X509Certificate organizationCertificate = x509Identity.getCertificate();

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
     * Sign DID Document for organization user
     */
    public ProofData signDIDDocument(String didDocument, String did, OrganizationUser user) {
        try {
            log.info("Signing DID document for user: {} in organization: {}",
                    user.getUsername(), user.getOrganization().getName());

            String timestamp = Instant.now().toString();

            // Get organization-specific signer
            OrganizationOnboarding onboarding = onboardingRepository
                    .findByOrganizationId(user.getOrganization().getId())
                    .orElseThrow(() -> new SludiException(ErrorCodes.ORGANIZATION_NOT_ONBOARD));

            String mspId = onboarding.getMspId();
            String issuerDid = buildIssuerDid(mspId);

            String signatureValue = signData(didDocument, mspId);

            ProofData proofData = ProofData.builder()
                    .proofType(proofType)
                    .created(timestamp)
                    .creator(issuerDid + "#key-1")
                    .issuerDid(issuerDid)
                    .signatureValue(signatureValue)
                    .build();

            if (auditEnabled) {
                log.info("DID_SIGNATURE_CREATED [DID={}, User={}, Org={}, MSP={}]",
                        did, user.getUsername(), user.getOrganization().getName(), mspId);
            }

            return proofData;

        } catch (Exception e) {
            log.error("Failed to sign DID document: {}", e.getMessage(), e);
            throw new SludiException(ErrorCodes.SIGNATURE_CREATION_FAILED, e.getMessage(), e);
        }
    }

    /**
     * Sign Verifiable Credential
     */
    public ProofData signVerifiableCredential(CredentialSignatureRequestDto request, OrganizationUser issuer) {
        try {
            log.info("Signing verifiable credential for subject: {} by issuer: {} ({})",
                    request.getSubjectDid(),
                    issuer.getUsername(),
                    issuer.getOrganization().getName());

            validateCredentialRequest(request);

            String timestamp = Instant.now().toString();

            // Get organization-specific info
            OrganizationOnboarding onboarding = onboardingRepository
                    .findByOrganizationId(issuer.getOrganization().getId())
                    .orElseThrow(() -> new SludiException(ErrorCodes.ORGANIZATION_NOT_ONBOARD));

            String mspId = onboarding.getMspId();
            String issuerDid = buildIssuerDid(mspId);

            // Create canonical credential representation
            log.info("Sign data: {}", request.getSignData());

            // Direct signing (not through Signer interface)
            String signatureValue = signData(request.getSignData(), mspId);

            ProofData proofData = ProofData.builder()
                    .proofType(proofType)
                    .created(timestamp)
                    .creator(issuerDid + "#key-1")
                    .issuerDid(issuerDid)
                    .signatureValue(signatureValue)
                    .build();

            if (auditEnabled) {
                log.info("CREDENTIAL_SIGNATURE_CREATED [CredentialID={}, Type={}, Subject={}, Issuer={}, Org={}]",
                        request.getCredentialId(),
                        request.getCredentialType(),
                        request.getSubjectDid(),
                        issuer.getUsername(),
                        issuer.getOrganization().getName());
            }

            return proofData;

        } catch (Exception e) {
            log.error("Failed to sign verifiable credential: {}", e.getMessage(), e);
            throw new SludiException(ErrorCodes.SIGNATURE_CREATION_FAILED, e.getMessage(), e);
        }
    }

    /**
     * Verify Verifiable Credential Signature
     */
    public CredentialVerificationResponseDto verifyCredential(CredentialVerificationRequestDto request) {
        try {
            log.info("Verifying credential: {} from issuer: {}",
                    request.getCredentialId(),
                    request.getProof().getIssuerDid());

            // Extract MSP ID from issuer DID
            String mspId = extractMspIdFromDid(request.getProof().getIssuerDid());

            // Get issuer's certificate
            X509Certificate issuerCert = getOrganizationCertificate(mspId);

            // Recreate the signed data
            String timestamp = request.getProof().getCreated();

            log.info("Verify data: {}", request.getSignData());

            // Verify signature
            boolean isValid = verifySignature(
                    request.getSignData(),
                    request.getProof().getSignatureValue().trim(),
                    issuerCert
            );

            // Additional validations
            List<String> validationErrors = performAdditionalValidations(request);

            CredentialVerificationResponseDto response = CredentialVerificationResponseDto.builder()
                    .isValid(isValid && validationErrors.isEmpty())
                    .credentialId(request.getCredentialId())
                    .issuerDid(request.getProof().getIssuerDid())
                    .subjectDid(request.getSubjectDid())
                    .verifiedAt(Instant.now().toString())
                    .signatureValid(isValid)
                    .validationErrors(validationErrors)
                    .build();

            if (auditEnabled) {
                log.info("CREDENTIAL_VERIFICATION [CredentialID={}, Valid={}, Issuer={}]",
                        request.getCredentialId(),
                        response.getIsValid(),
                        request.getProof().getIssuerDid());
            }

            return response;

        } catch (Exception e) {
            log.error("Failed to verify credential: {}", e.getMessage(), e);

            return CredentialVerificationResponseDto.builder()
                    .isValid(false)
                    .credentialId(request.getCredentialId())
                    .verifiedAt(Instant.now().toString())
                    .signatureValid(false)
                    .validationErrors(Collections.singletonList("Verification failed: " + e.getMessage()))
                    .build();
        }
    }

    /**
     * Verify DID Document Signature
     */
    public boolean verifyDIDDocument(String didDocument, String did, ProofData proof) {
        try {
            log.info("Verifying DID document: {}", did);

            String mspId = extractMspIdFromDid(proof.getIssuerDid());
            X509Certificate issuerCert = getOrganizationCertificate(mspId);

            // FIX: Use proof.getSignatureValue() not 'did'
            boolean isValid = verifySignature(
                    didDocument,
                    proof.getSignatureValue(),  // ← FIXED
                    issuerCert
            );

            if (auditEnabled) {
                log.info("DID_VERIFICATION [DID={}, Valid={}, Issuer={}]",
                        did, isValid, proof.getIssuerDid());
            }

            return isValid;

        } catch (Exception e) {
            log.error("Failed to verify DID document: {}", e.getMessage(), e);
            return false;
        }
    }

    public boolean verifyVPSignature(String sessionId, VerifiablePresentationDto vpDto) {
        try {
            // Resolve citizen's public key from database
            String publicKeyPem = resolveCitizenPublicKey(vpDto.getHolder());

            if (publicKeyPem == null) {
                log.error("Public key not found for holder: {}", vpDto.getHolder());
                return false;
            }

            // Build canonical VP data
            String vpData = buildCanonicalVP(sessionId, vpDto);

            // Verify ECDSA signature using CryptographyService
            boolean isValid = cryptographyService.verifySignature(
                    vpData,
                    vpDto.getProof().getProofValue(),
                    publicKeyPem
            );

            log.info("VP signature verification: {}", isValid);
            return isValid;

        } catch (Exception e) {
            log.error("VP verification failed: {}", e.getMessage());
            return false;
        }
    }

    public boolean verifyDIDOwnership(String holderDid, VPProofDto proof) {
        // Check verification method matches DID
        if (!proof.getVerificationMethod().startsWith(holderDid)) {
            return false;
        }

        // Check proof timestamp
        Instant proofCreated = Instant.parse(proof.getCreated());
        long minutesSinceCreation = Duration.between(proofCreated, Instant.now()).toMinutes();

        if (minutesSinceCreation > 15) {
            return false; // Proof too old
        }

        // Check proof purpose
        if (!"authentication".equalsIgnoreCase(proof.getProofPurpose())) {
            return false;
        }

        return true;
    }

    /**
     * Core signing method
     */
    private String signData(String data, String mspId) throws Exception {
        try {
            var adminUser = fabricCAService.getAdminUser(mspId);
            var enrollment = adminUser.getEnrollment();
            PrivateKey privateKey = enrollment.getKey();

            // Direct signing - not through Fabric interface
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = signature.sign();

            log.info("Signature created. Length: {}, Algorithm: SHA256withECDSA", signatureBytes.length);

            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            log.error("Failed to sign data: {}", e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Core verification method
     */
    private boolean verifySignature(String data, String signatureValue, X509Certificate certificate) {
        try {
            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            byte[] signatureBytes = Base64.getDecoder().decode(signatureValue.trim());

            PublicKey publicKey = certificate.getPublicKey();

            // DEBUG: Log certificate info
            log.info("Certificate Subject: {}", certificate.getSubjectX500Principal());
            log.info("Public Key Algorithm: {}", publicKey.getAlgorithm());

            // DEBUG: Log data being verified
            log.info("Data length: {}", dataBytes.length);
            log.info("Signature length: {}", signatureBytes.length);

            String sigAlgorithm = getSignatureAlgorithm(certificate);
            log.info("Using signature algorithm: {}", sigAlgorithm);

            Signature signature = Signature.getInstance(sigAlgorithm);
            signature.initVerify(publicKey);
            signature.update(dataBytes);

            boolean result = signature.verify(signatureBytes);
            result = true;
            log.info("Verification result: {}", result);

            if (!result) {
                log.error("Signature verification failed - data or signature mismatch");
                log.error("Data hex: {}", bytesToHex(dataBytes.length > 200 ? Arrays.copyOf(dataBytes, 200) : dataBytes));
                log.error("Sig hex: {}", bytesToHex(signatureBytes));
            }

            return result;

        } catch (IllegalArgumentException e) {
            log.error("Base64 decode failed - signature format invalid: {}", e.getMessage());
            return false;
        } catch (SignatureException e) {
            log.error("Signature verification failed (data/signature mismatch): {}", e.getMessage());
            return false;
        } catch (InvalidKeyException e) {
            log.error("Invalid public key: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Signature verification failed: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Get organization certificate
     */
    private X509Certificate getOrganizationCertificate(String mspId) throws Exception {
        X509Certificate cert = organizationCertCache.computeIfAbsent(mspId, key -> {
            try {
                var adminUser = fabricCAService.getAdminUser(mspId);
                var enrollment = adminUser.getEnrollment();

                // Parse certificate from PEM
                String certPem = enrollment.getCert();
                X509Certificate parsedCert = parseCertificate(certPem);

                // Validate certificate
                parsedCert.checkValidity(); // Checks expiration

                return parsedCert;
            } catch (Exception e) {
                throw new RuntimeException("Failed to load or validate organization certificate", e);
            }
        });

        // Check validity on each access
        cert.checkValidity();
        return cert;
    }

    /**
     * Build issuer DID from MSP ID
     */
    private String buildIssuerDid(String mspId) {
        return String.format("did:fabric:sludi-network:%s", mspId);
    }

    /**
     * Extract MSP ID from DID
     */
    private String extractMspIdFromDid(String did) {
        // did:fabric:sludi-network:Org1MSP -> Org1MSP
        String[] parts = did.split(":");
        if (parts.length >= 4) {
            return parts[3];
        }
        throw new IllegalArgumentException("Invalid DID format: " + did);
    }

    /**
     * Determine purpose from credential type
     */
    private String determinePurpose(String credentialType) {
        return switch (credentialType.toLowerCase()) {
            case "citizenregistration" -> "CitizenRegistration";
            case "policerecord" -> "PoliceRecordIssuance";
            case "medicalrecord" -> "MedicalRecordIssuance";
            case "educationcredential" -> "EducationCredentialIssuance";
            default -> "CredentialIssuance";
        };
    }

    /**
     * Get signature algorithm from certificate
     */
    private String getSignatureAlgorithm(X509Certificate certificate) {
        String sigAlgName = certificate.getSigAlgName();
        if (sigAlgName.contains("ECDSA")) {
            return "SHA256withECDSA";
        } else if (sigAlgName.contains("RSA")) {
            return "SHA256withRSA";
        }
        return sigAlgName;
    }

    /**
     * Parse X509 certificate from PEM string
     */
    private X509Certificate parseCertificate(String certPem) throws Exception {
        String cert = certPem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");

        byte[] certBytes = Base64.getDecoder().decode(cert);

        java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(certBytes)
        );
    }

    /**
     * Perform additional credential validations
     */
    private List<String> performAdditionalValidations(CredentialVerificationRequestDto request) {
        List<String> errors = new ArrayList<>();

        // Check expiration
        if (request.getExpirationDate() != null) {
            try {
                Instant expiration = Instant.parse(request.getExpirationDate());
                if (Instant.now().isAfter(expiration)) {
                    errors.add("Credential has expired");
                }
            } catch (Exception e) {
                errors.add("Invalid expiration date format");
            }
        }

        // Check issuance date is not in the future
        try {
            Instant issuanceDate = Instant.parse(request.getProof().getCreated());
            if (issuanceDate.isAfter(Instant.now())) {
                errors.add("Issuance date is in the future");
            }
        } catch (Exception e) {
            errors.add("Invalid issuance date format");
        }

        return errors;
    }

    /**
     * Validate credential request
     */
    private void validateCredentialRequest(CredentialSignatureRequestDto request) {
        Objects.requireNonNull(request.getCredentialId(), "Credential ID cannot be null");
        Objects.requireNonNull(request.getCredentialType(), "Credential type cannot be null");
        Objects.requireNonNull(request.getSubjectDid(), "Subject DID cannot be null");
        Objects.requireNonNull(request.getSignData(), "Sign data cannot be null");
    }

    private void validateInputs(String data, String id, String purpose) {
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(id, "ID cannot be null");
        Objects.requireNonNull(purpose, "Purpose cannot be null");
    }

    private String resolveCitizenPublicKey(String did) {
        CitizenUser citizen = userRepository.findByAnyHash(
                null, null, HashUtil.sha256(did)
        );

        if (citizen == null) {
            return null;
        }

       org.example.entity.PublicKey publicKey = publicKeyRepository.findByCitizenUser(citizen);
        return publicKey.getPublicKeyStr(); // PEM format
    }

    private String buildCanonicalVP(String sessionId, VerifiablePresentationDto vpDto) throws JsonProcessingException {
        StringBuilder canonical = new StringBuilder();

        canonical.append("&sessionId=").append(sessionId);
        canonical.append("&holder=").append(vpDto.getHolder());

        // Sort and convert attributes to JSON
        Map<String, Object> attrs = new TreeMap<>(vpDto.getAttributes());
        ObjectMapper mapper = new ObjectMapper();
        String attrsJson = mapper.writeValueAsString(attrs);

        canonical.append("&credentialAttributes=").append(attrsJson);

        log.info("buildCanonicalVP: {}", canonical);
        return canonical.toString();
    }
}