package org.example.integration;

import org.example.dto.*;
import org.example.entity.AuthenticationLog;
import org.example.entity.DIDDocument;
import org.example.entity.VerifiableCredential;
import org.example.entity.SystemStats;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;

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
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

@Service
public class HyperledgerService {

    private static final Logger LOGGER = Logger.getLogger(HyperledgerService.class.getName());

    @Autowired
    private Contract contract;

    @Autowired
    private Gateway gateway;

    @Value("${fabric.chaincode-name}")
    private String chaincodeName;

    @Value("${sludi.issuer-did:did:sludi:government789}")
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

            // Get transaction info from the gateway
            String transactionId = generateTransactionId();
            Long blockNumber = getCurrentBlockNumber();

            LOGGER.info("Successfully registered citizen with DID: " + didDocument.getId());

            return HyperledgerTransactionResult.builder()
                    .transactionId(transactionId)
                    .blockNumber(blockNumber)
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

            String transactionId = generateTransactionId();
            Long blockNumber = getCurrentBlockNumber();

            LOGGER.info("Successfully issued credential: " + credential.getId());

            return HyperledgerTransactionResult.builder()
                    .transactionId(transactionId)
                    .blockNumber(blockNumber)
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
            String resultMessage = new String(result);

            String transactionId = generateTransactionId();
            Long blockNumber = getCurrentBlockNumber();

            LOGGER.info("Successfully revoked credential: " + credentialId);

            return HyperledgerTransactionResult.builder()
                    .transactionId(transactionId)
                    .blockNumber(blockNumber)
                    .status("SUCCESS")
                    .message(resultMessage)
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
    public SystemStats getSystemStats() {
        try {
            LOGGER.info("Getting system statistics");

            byte[] result = contract.evaluateTransaction("GetSystemStats");
            String statsJson = new String(result);
            SystemStats stats = objectMapper.readValue(statsJson, SystemStats.class);

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
            SystemStats stats = getSystemStats();

            return BlockchainNetworkInfo.builder()
                    .networkName("SLUDI-Network")
                    .channelName(chaincodeName)
                    .chaincodeVersion("1.0.0")
                    .totalDIDs(stats.getTotalDIDs())
                    .totalCredentials(stats.getTotalCredentials())
                    .lastUpdated(stats.getTimestamp())
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
     * Generate a unique transaction ID
     */
    private String generateTransactionId() {
        return "tx_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    /**
     * Get current block number (using timestamp as block number)
     */
    private Long getCurrentBlockNumber() {
        return System.currentTimeMillis() / 1000; // Simple timestamp as block number
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