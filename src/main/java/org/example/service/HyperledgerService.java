package org.example.service;

import org.example.dto.*;
import org.example.entity.AuthenticationLog;
import org.example.entity.DIDDocument;
import org.example.entity.VerifiableCredential;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;

import org.example.repository.DIDDocumentRepository;
import org.example.repository.VerifiableCredentialRepository;
import org.hyperledger.fabric.client.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

@Service
public class HyperledgerService {

    private static final Logger LOGGER = Logger.getLogger(HyperledgerService.class.getName());

    @Autowired
    private DIDDocumentRepository didRepository;

    @Autowired
    private VerifiableCredentialRepository credentialRepository;

    @Autowired
    private Contract contract;

    @Autowired
    private Gateway gateway;

    @Value("${fabric.chaincode-name}")
    private String chaincodeName;

    @Value("${sludi.issuer-did}")
    private String issuerDid;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Register a new citizen on the blockchain
     */
    public HyperledgerTransactionResult registerCitizen(CitizenRegistrationDto registration) {
        try {
            LOGGER.info("Registering citizen with ID: " + registration.getUserId());

            // Create citizen registration object for the chaincode
            CitizenRegistrationChaincode chaincodeRegistration = CitizenRegistrationChaincode.builder()
                    .userId(registration.getUserId())
                    .fullName(registration.getFullName())
                    .dateOfBirth(registration.getDateOfBirth())
                    .nic(registration.getNic())
                    .publicKeyBase58(registration.getPublicKeyBase58())
                    .fingerprintHash(registration.getFingerprintHash())
                    .faceImageHash(registration.getFaceImageHash())
                    .build();

            // Convert to JSON for chaincode
            String registrationJson = objectMapper.writeValueAsString(chaincodeRegistration);

            // Submit transaction to blockchain
            byte[] result = contract.submitTransaction("RegisterCitizen", registrationJson);

            // Parse the result
            String resultString = new String(result);
            DIDDocument didDocument = objectMapper.readValue(resultString, DIDDocument.class);

            if (didDocument.getPublicKey() != null) {
                didDocument.getPublicKey().forEach(pk -> pk.setDidDocument(didDocument));
            }

            if (didDocument.getService() != null) {
                didDocument.getService().forEach(s -> s.setDidDocument(didDocument));
            }

            // Save the DID document to the database
            didRepository.save(didDocument);

            LOGGER.info("Successfully registered citizen with DID: " + didDocument.getId());

            return HyperledgerTransactionResult.builder()
                    .transactionId(didDocument.getBlockchainTxId())
                    .blockNumber(didDocument.getBlockNumber())
                    .status("SUCCESS")
                    .message("Citizen registered successfully")
                    .timestamp(Instant.now())
                    .didId(didDocument.getId())
                    .build();

        } catch (Exception e) {
            LOGGER.severe("Failed to register citizen: " + e.getMessage());
            throw new SludiException(ErrorCodes.BLOCKCHAIN_REGISTRATION_FAILED, e);
        }
    }

    /**
     * Issue a verifiable credential to a citizen
     */
    public HyperledgerTransactionResult issueCredential(CredentialIssuanceRequestDto request) {
        try {
            LOGGER.info("Issuing credential: " + request.getCredentialId());

            byte[] result = contract.submitTransaction(
                    "IssueCredential",
                    request.getCredentialId(),
                    request.getSubjectDID(),
                    request.getCredentialType(),
                    request.getFullName(),
                    request.getNic(),
                    request.getDateOfBirth(),
                    request.getCitizenship(),
                    request.getFingerprintHash(),
                    request.getFaceImageHash(),
                    request.getAddress().getStreet(),
                    request.getAddress().getCity(),
                    request.getAddress().getState(),
                    request.getAddress().getPostalCode()
            );

            String resultString = new String(result);
            VerifiableCredential credential = objectMapper.readValue(resultString, VerifiableCredential.class);

            LOGGER.info("Successfully issued credential: " + credential.getId());

            // Save the credential to the database
            credentialRepository.save(credential);

            return HyperledgerTransactionResult.builder()
                    .transactionId(credential.getBlockchainTxId())
                    .blockNumber(credential.getBlockNumber())
                    .status("SUCCESS")
                    .message("Credential issued successfully")
                    .timestamp(Instant.now())
                    .credentialId(credential.getId())
                    .build();

        } catch (Exception e) {
            LOGGER.severe("Failed to issue credential: " + e.getMessage());
            throw new SludiException(ErrorCodes.CREDENTIAL_ISSUANCE_FAILED, e);
        }
    }

    /**
     * Verify a citizen's identity using biometric data
     */
    public String verifyCitizen(String didId, String verifierDid, String biometricType,
                                String biometricHash, String challenge) {
        try {
            LOGGER.info("Verifying citizen with DID: " + didId);

            // For biometric verification, we need both fingerprint and face image hashes
            String fingerprintHash = "";
            String faceImageHash = "";

            if ("fingerprint".equals(biometricType)) {
                fingerprintHash = biometricHash;
                faceImageHash = challenge; // Using challenge as secondary biometric
            } else if ("face".equals(biometricType)) {
                faceImageHash = biometricHash;
                fingerprintHash = challenge; // Using challenge as secondary biometric
            } else {
                // Both provided
                fingerprintHash = biometricHash;
                faceImageHash = challenge;
            }

            byte[] result = contract.submitTransaction(
                    "VerifyCitizen",
                    didId,
                    verifierDid,
                    biometricType,
                    fingerprintHash,
                    faceImageHash
            );

            String verificationResult = new String(result);
            LOGGER.info("Verification result for DID " + didId + ": " + verificationResult);

            return verificationResult;

        } catch (Exception e) {
            LOGGER.severe("Failed to verify citizen: " + e.getMessage());
            throw new SludiException(ErrorCodes.BIOMETRIC_VERIFICATION_FAILED,
                    "Failed to verify citizen on blockchain", e);
        }
    }

    /**
     * Verify credential authenticity
     */
    public boolean verifyCredential(String credentialId, String expectedSubjectDid) {
        try {
            LOGGER.info("Verifying credential: " + credentialId);

            byte[] result = contract.evaluateTransaction("ReadCredential", credentialId);
            String credentialJson = new String(result);
            VerifiableCredential credential = objectMapper.readValue(credentialJson, VerifiableCredential.class);

            boolean isValid = "active".equals(credential.getStatus()) &&
                    credential.getCredentialSubject().getId().equals(expectedSubjectDid) &&
                    isCredentialNotExpired(credential.getExpirationDate());

            LOGGER.info("Credential verification result: " + isValid);
            return isValid;

        } catch (Exception e) {
            LOGGER.warning("Failed to verify credential: " + e.getMessage());
            return false;
        }
    }

    /**
     * Read DID document from blockchain
     */
    public DIDDocument getDIDDocument(String didId) {
        try {
            LOGGER.info("Reading DID document: " + didId);

            byte[] result = contract.evaluateTransaction("ReadDID", didId);
            String didJson = new String(result);
            DIDDocument didDocument = objectMapper.readValue(didJson, DIDDocument.class);

            LOGGER.info("Successfully retrieved DID document: " + didId);
            return didDocument;

        } catch (Exception e) {
            LOGGER.severe("Failed to read DID document: " + e.getMessage());
            throw new SludiException(ErrorCodes.DID_NOT_FOUND, e);
        }
    }

    /**
     * Update DID document on blockchain
     */
    public void updateDID(String didId, String newPublicKey, String metadata) {
        try {
            LOGGER.info("Updating DID: " + didId);

            String serviceEndpoint = metadata != null ? metadata : "";

            byte[] result = contract.submitTransaction(
                    "UpdateDID",
                    didId,
                    newPublicKey != null ? newPublicKey : "",
                    serviceEndpoint
            );

            String resultString = new String(result);
            DIDDocument updatedDid = objectMapper.readValue(resultString, DIDDocument.class);

            LOGGER.info("Successfully updated DID: " + updatedDid.getId());

        } catch (Exception e) {
            LOGGER.severe("Failed to update DID: " + e.getMessage());
            throw new SludiException(ErrorCodes.DID_UPDATE_FAILED, e);
        }
    }

    /**
     * Deactivate DID document
     */
    public void deactivateDID(String didId) {
        try {
            LOGGER.info("Deactivating DID: " + didId);

            byte[] result = contract.submitTransaction("DeactivateDID", didId);
            String resultMessage = new String(result);

            LOGGER.info("Successfully deactivated DID: " + didId + " - " + resultMessage);

        } catch (Exception e) {
            LOGGER.severe("Failed to deactivate DID: " + e.getMessage());
            throw new SludiException(ErrorCodes.DID_DEACTIVATION_FAILED, e);
        }
    }

    /**
     * Check if DID exist on blockchain
     */
    public boolean didExists(String didId) {
        try {
            byte[] result = contract.evaluateTransaction("DIDExists", didId);
            return Boolean.parseBoolean(new String(result));

        } catch (Exception e) {
            LOGGER.warning("Failed to check DID existence: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get all credentials for a specific DID
     */
    public List<VerifiableCredential> getCredentialsByDID(String subjectDID) {
        try {
            LOGGER.info("Getting credentials for DID: " + subjectDID);

            byte[] result = contract.evaluateTransaction("GetCredentialsByDID", subjectDID);
            String credentialsJson = new String(result);

            List<VerifiableCredential> credentials = objectMapper.readValue(
                    credentialsJson,
                    new TypeReference<List<VerifiableCredential>>() {}
            );

            LOGGER.info("Found " + credentials.size() + " credentials for DID: " + subjectDID);
            return credentials;

        } catch (Exception e) {
            LOGGER.severe("Failed to get credentials: " + e.getMessage());
            throw new SludiException(ErrorCodes.CREDENTIAL_RETRIEVAL_FAILED, e);
        }
    }

    /**
     * Revoke a credential
     */
    public HyperledgerTransactionResult revokeCredential(String credentialId, String reason) {
        try {
            LOGGER.info("Revoking credential: " + credentialId);

            byte[] result = contract.submitTransaction("RevokeCredential", credentialId, reason);

            String resultString = new String(result);
            VerifiableCredential credential = objectMapper.readValue(resultString, VerifiableCredential.class);

            // Update the credential status to revoked
            VerifiableCredential existingCredential = credentialRepository.findById(credentialId)
                    .orElseThrow(() -> new SludiException(ErrorCodes.CREDENTIAL_NOT_FOUND));

            existingCredential.setStatus("revoked");
            existingCredential.setRevokedBy(credential.getRevokedBy());
            existingCredential.setRevocationReason(credential.getRevocationReason());
            existingCredential.setRevokedAt(credential.getRevokedAt());
            existingCredential.setRevocationTxId(credential.getRevocationTxId());
            existingCredential.setRevocationBlockNumber(credential.getRevocationBlockNumber());

            credentialRepository.save(existingCredential);

            LOGGER.info("Successfully revoked credential: " + credentialId);

            return HyperledgerTransactionResult.builder()
                    .transactionId(credential.getRevocationTxId())
                    .blockNumber(credential.getRevocationBlockNumber())
                    .status("SUCCESS")
                    .message("Successfully revoked credential")
                    .timestamp(Instant.now())
                    .credentialId(credentialId)
                    .build();

        } catch (Exception e) {
            LOGGER.severe("Failed to revoke credential: " + e.getMessage());
            throw new SludiException(ErrorCodes.CREDENTIAL_REVOCATION_FAILED, e);
        }
    }

    /**
     * Initialize the blockchain ledger
     */
    public void initializeLedger() {
        try {
            LOGGER.info("Initializing blockchain ledger");

            contract.submitTransaction("InitLedger");

            LOGGER.info("Successfully initialized blockchain ledger");

        } catch (Exception e) {
            LOGGER.severe("Failed to initialize ledger: " + e.getMessage());
            throw new SludiException(ErrorCodes.LEDGER_INITIALIZATION_FAILED, e);
        }
    }

    /**
     * Get system statistics from blockchain
     */
    public SystemStatsDto getSystemStats() {
        try {
            LOGGER.info("Getting system statistics");

            byte[] result = contract.evaluateTransaction("GetSystemStats");
            String statsJson = new String(result);
            SystemStatsDto stats = objectMapper.readValue(statsJson, SystemStatsDto.class);

            LOGGER.info("Successfully retrieved system statistics");
            return stats;

        } catch (Exception e) {
            LOGGER.severe("Failed to get system statistics: " + e.getMessage());
            throw new SludiException(ErrorCodes.SYSTEM_STATS_FAILED, e);
        }
    }

    /**
     * Get authentication logs for a user
     */
    public List<AuthenticationLog> getAuthenticationLogs(String userDID) {
        try {
            LOGGER.info("Getting authentication logs for DID: " + userDID);

            byte[] result = contract.evaluateTransaction("GetAuthenticationLogs", userDID);
            String logsJson = new String(result);

            List<AuthenticationLog> logs = objectMapper.readValue(
                    logsJson,
                    new TypeReference<List<AuthenticationLog>>() {}
            );

            LOGGER.info("Found " + logs.size() + " authentication logs for DID: " + userDID);
            return logs;

        } catch (Exception e) {
            LOGGER.severe("Failed to get authentication logs: " + e.getMessage());
            throw new SludiException(ErrorCodes.AUTH_LOG_RETRIEVAL_FAILED, e);
        }
    }

    /**
     * Get all DIDs from blockchain (admin function)
     */
    public List<DIDDocument> getAllDIDs() {
        try {
            LOGGER.info("Getting all DIDs from blockchain");

            byte[] result = contract.evaluateTransaction("GetAllDIDs");
            String didsJson = new String(result);

            List<DIDDocument> dids = objectMapper.readValue(
                    didsJson,
                    new TypeReference<List<DIDDocument>>() {}
            );

            LOGGER.info("Found " + dids.size() + " DIDs on blockchain");
            return dids;

        } catch (Exception e) {
            LOGGER.severe("Failed to get all DIDs: " + e.getMessage());
            throw new SludiException(ErrorCodes.DID_RETRIEVAL_FAILED, e);
        }
    }

    /**
     * Get all credentials from blockchain (admin function)
     */
    public List<VerifiableCredential> getAllCredentials() {
        try {
            LOGGER.info("Getting all credentials from blockchain");

            byte[] result = contract.evaluateTransaction("GetAllCredentials");
            String credentialsJson = new String(result);

            List<VerifiableCredential> credentials = objectMapper.readValue(
                    credentialsJson,
                    new TypeReference<List<VerifiableCredential>>() {}
            );

            LOGGER.info("Found " + credentials.size() + " credentials on blockchain");
            return credentials;

        } catch (Exception e) {
            LOGGER.severe("Failed to get all credentials: " + e.getMessage());
            throw new SludiException(ErrorCodes.CREDENTIAL_RETRIEVAL_FAILED,
                    "Failed to retrieve credentials from blockchain", e);
        }
    }

    /**
     * Register citizen asynchronously
     */
    public CompletableFuture<HyperledgerTransactionResult> registerCitizenAsync(CitizenRegistrationDto registration) {
        return CompletableFuture.supplyAsync(() -> registerCitizen(registration));
    }

    /**
     * Verify citizen asynchronously
     */
    public CompletableFuture<String> verifyCitizenAsync(String didId, String verifierDid,
                                                        String biometricType, String biometricHash,
                                                        String challenge) {
        return CompletableFuture.supplyAsync(() ->
                verifyCitizen(didId, verifierDid, biometricType, biometricHash, challenge));
    }

    /**
     * Check blockchain connectivity and health
     */
    public boolean isBlockchainHealthy() {
        try {
            // Try to get system stats as a health check
            getSystemStats();
            return true;
        } catch (Exception e) {
            LOGGER.warning("Blockchain health check failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get blockchain network info
     */
    public BlockchainNetworkInfo getNetworkInfo() {
        try {
            SystemStatsDto stats = getSystemStats();

            return BlockchainNetworkInfo.builder()
                    .networkName("SLUDI-Network")
                    .channelName(chaincodeName)
                    .chaincodeVersion("1.0.0")
                    .totalDIDs(stats.getTotalDIDs())
                    .totalCredentials(stats.getTotalCredentials())
                    .lastUpdated(stats.getLastUpdated())
                    .status("HEALTHY")
                    .build();

        } catch (Exception e) {
            LOGGER.severe("Failed to get network info: " + e.getMessage());
            return BlockchainNetworkInfo.builder()
                    .networkName("SLUDI-Network")
                    .status("UNHEALTHY")
                    .lastUpdated(Instant.now().toString())
                    .build();
        }
    }

    /**
     * Check if the credential is not expired
     */
    private boolean isCredentialNotExpired(String expirationDate) {
        try {
            Instant expiration = Instant.parse(expirationDate);
            return Instant.now().isBefore(expiration);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Batch operations for multiple citizens (for bulk operations)
     */
    public List<HyperledgerTransactionResult> batchRegisterCitizens(List<CitizenRegistrationDto> registrations) {
        return registrations.stream()
                .map(this::registerCitizen)
                .toList();
    }

    /**
     * Close gateway connection (for cleanup)
     */
    public void closeConnection() {
        try {
            if (gateway != null) {
                gateway.close();
                LOGGER.info("Gateway connection closed successfully");
            }
        } catch (Exception e) {
            LOGGER.warning("Failed to close gateway connection: " + e.getMessage());
        }
    }
}