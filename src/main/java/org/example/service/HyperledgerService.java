package org.example.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.example.dto.*;
import org.example.entity.AuthenticationLog;
import org.example.entity.VerifiableCredential;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;

import org.example.repository.VerifiableCredentialRepository;
import org.hyperledger.fabric.client.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
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

    @Value("${sludi.issuer-did}")
    private String issuerDid;

    @Autowired
    private VerifiableCredentialRepository credentialRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * create a new DID on the blockchain
     */
    public HyperledgerTransactionResult createDID(String nic) {
        try {
            LOGGER.info("Registering citizen with ID: " + nic);

            // Submit transaction to blockchain
            byte[] result = contract.submitTransaction("CreateDID", nic);

            // Parse the result
            String resultString = new String(result);
            DIDDocumentDto didDocument = objectMapper.readValue(resultString, DIDDocumentDto.class);

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
     * Issue a verifiable credential
     */
    public VCBlockChainResult issueCredential(CredentialIssuanceRequestDto request) {
        try {
            // Convert to JSON for chaincode
            String credentialJson = objectMapper.writeValueAsString(request);

            byte[] result = contract.submitTransaction(
                    "IssueCredential",
                    credentialJson
            );

            String resultString = new String(result);
            VCBlockChainResult credential = objectMapper.readValue(resultString, VCBlockChainResult.class);

            LOGGER.info("Successfully issued credential: " + credential.getId());

            return credential;

        } catch (Exception e) {
            LOGGER.severe("Failed to issue credential: " + e.getMessage());
            throw new SludiException(ErrorCodes.CREDENTIAL_ISSUANCE_FAILED, e);
        }
    }

    /**
     * Read DID document from blockchain
     */
    public DIDDocumentDto getDIDDocument(String didId) {
        try {
            LOGGER.info("Reading DID document: " + didId);

            byte[] result = contract.evaluateTransaction("ReadDID", didId);
            String didJson = new String(result);
            DIDDocumentDto didDocument = objectMapper.readValue(didJson, DIDDocumentDto.class);

            LOGGER.info("Successfully retrieved DID document: " + didDocument.getId());
            return didDocument;

        } catch (Exception e) {
            LOGGER.severe("Failed to read DID document: " + e.getMessage());
            throw new SludiException(ErrorCodes.DID_NOT_FOUND, e);
        }
    }

    /**
     * Read Identity Credential from blockchain
     */
    public VCBlockChainResult readCredential(String credentialId) {
        try {
            LOGGER.info("Reading identity credential: " + credentialId);

            byte[] result = contract.evaluateTransaction("ReadCredential", credentialId);
            String credentialJson = new String(result);
            VCBlockChainResult credential = objectMapper.readValue(credentialJson, VCBlockChainResult.class);

            LOGGER.info("Successfully retrieved credential: " + credential.getId());
            return credential;

        } catch (Exception e) {
            LOGGER.severe("Failed to read identity credential: " + e.getMessage());
            throw new SludiException(ErrorCodes.CREDENTIAL_NOT_FOUND, e);
        }
    }

    /**
     * Get all credentials for a specific DID
     */
    public List<VerifiableCredential> getCredentialsByDID(String subjectDID) {
        try {
            LOGGER.info("Getting credentials for DID: " + subjectDID);

            byte[] result = contract.evaluateTransaction("GetCredentialsByDID", subjectDID);
            String credentialsJson = new String(result, StandardCharsets.UTF_8);

            if (credentialsJson.trim().isEmpty() || credentialsJson.equals("null")) {
                return new ArrayList<>();
            }

            List<VerifiableCredential> credentials = objectMapper.readValue(
                    credentialsJson,
                    new TypeReference<List<VerifiableCredential>>() {}
            );

            if (credentials == null) {
                return new ArrayList<>();
            }

            return credentials;

        } catch (JsonProcessingException e) {
            throw new SludiException(ErrorCodes.JSON_PARSING_FAILED, e);
        } catch (Exception e) {
            LOGGER.severe("Failed to get credentials: " + e.getMessage());
            throw new SludiException(ErrorCodes.CREDENTIAL_RETRIEVAL_FAILED, e);
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
                    "UpdateDIDPublicKey",
                    didId,
                    newPublicKey != null ? newPublicKey : "",
                    serviceEndpoint
            );

            String resultString = new String(result);
            DIDDocumentDto updatedDid = objectMapper.readValue(resultString, DIDDocumentDto.class);

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
    public List<DIDDocumentDto> getAllDIDs() {
        try {
            LOGGER.info("Getting all DIDs from blockchain");

            byte[] result = contract.evaluateTransaction("GetAllDIDs");
            String didsJson = new String(result);

            List<DIDDocumentDto> dids = objectMapper.readValue(
                    didsJson,
                    new TypeReference<List<DIDDocumentDto>>() {}
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