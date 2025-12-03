package org.example.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.entity.*;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;

import org.hyperledger.fabric.client.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class HyperledgerService {

    private final Contract contract;
    private final Gateway gateway;

    @Value("${fabric.chaincode-name}")
    private String chaincodeName;

    @Value("${sludi.issuer-did}")
    private String issuerDid;

    private final ObjectMapper objectMapper;
    private final Gson gson = new Gson();

    public HyperledgerService(
            Contract contract,
            Gateway gateway
    ) {
        this.contract = contract;
        this.gateway = gateway;

        // Initialize ObjectMapper with deterministic serialization settings
        this.objectMapper = new ObjectMapper();
        // Enable ordering map entries by keys for deterministic JSON output
        this.objectMapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
        // Ensure compact output (no extra whitespace) for byte-level consistency
        this.objectMapper.configure(SerializationFeature.INDENT_OUTPUT, false);
    }

    /**
     * create a new DID on the blockchain
     */
    public DIDDocumentDto createDID(
            String didId,
            String didVersion,
            List<PublicKeyDto> publicKeys,
            List<String> authentication,
            List<ServiceDto> services,
            ProofData proof) {
        try {
            log.info("Registering citizen with DID: {}", didId);

            String publicKeysJson = objectMapper.writeValueAsString(publicKeys);
            String authenticationJson = objectMapper.writeValueAsString(authentication);
            String servicesJson = objectMapper.writeValueAsString(services);
            String proofJson = objectMapper.writeValueAsString(proof);

            // Submit transaction to blockchain
            byte[] result = contract.submitTransaction(
                    "CreateDID",
                    didId,
                    didVersion,
                    publicKeysJson,
                    authenticationJson,
                    servicesJson,
                    proofJson
            );

            // Parse the returned DID document
            String didJson = new String(result, StandardCharsets.UTF_8);
            DIDDocumentDto didDocument = objectMapper.readValue(didJson, DIDDocumentDto.class);

            log.info("Successfully registered citizen with DID: {}", didDocument.getId());

            return didDocument;

        } catch (Exception e) {
            log.error("Failed to register citizen: {}", e.getMessage());
            throw new SludiException(ErrorCodes.BLOCKCHAIN_REGISTRATION_FAILED, e);
        }
    }

    /**
     * Issue a verifiable credential
     */
    public VCBlockChainResult issueCredential(CredentialIssuanceRequestDto request) {
        try {
            log.info("Issue credential for DID: {}", request.getSubjectDID());

            String contextJson = objectMapper.writeValueAsString(request.getContext());
            String supportingDocsJson = objectMapper.writeValueAsString(request.getSupportingDocuments());
            String proofJson = objectMapper.writeValueAsString(request.getProofData());

            String issuanceDate = Instant.now().toString();

            byte[] result = contract.submitTransaction(
                    "IssueCredential",
                    request.getCredentialId(),
                    contextJson,
                    request.getCredentialType(),
                    request.getIssuerDID(),
                    issuanceDate,
                    request.getExpireDate(),
                    request.getSubjectDID(),
                    request.getCredentialSubjectHash(),
                    supportingDocsJson,
                    proofJson
            );

            // Parse the returned credential
            String credentialJson = new String(result, StandardCharsets.UTF_8);
            VCBlockChainResult credential = objectMapper.readValue(credentialJson, VCBlockChainResult.class);

            log.info("Successfully issued credential: {}", credential.getId());

            return credential;

        } catch (Exception e) {
            log.error("Failed to issue credential: {}", e.getMessage());
            throw new SludiException(ErrorCodes.CREDENTIAL_ISSUANCE_FAILED, e);
        }
    }

    /**
     * Read DID document from blockchain
     */
    public DIDDocumentDto getDIDDocument(String didId) {
        try {
            log.info("Reading DID document: {}", didId);

            byte[] result = contract.evaluateTransaction("GetDID", didId);
            String didJson = new String(result);
            DIDDocumentDto didDocument = objectMapper.readValue(didJson, DIDDocumentDto.class);

            log.info("Successfully retrieved DID document: {}", didDocument.getId());
            return didDocument;

        } catch (Exception e) {
            log.error("Failed to read DID document: {}", e.getMessage());
            throw new SludiException(ErrorCodes.DID_NOT_FOUND, e);
        }
    }

    /**
     * Read Identity Credential from blockchain
     */
    public VCBlockChainResult readCredential(String credentialId) {
        try {
            log.info("Reading identity credential: {}", credentialId);

            byte[] result = contract.evaluateTransaction("GetCredential", credentialId);
            String credentialJson = new String(result);
            VCBlockChainResult credential = objectMapper.readValue(credentialJson, VCBlockChainResult.class);

            log.info("Successfully retrieved credential: {}", credential.getId());
            return credential;

        } catch (Exception e) {
            log.error("Failed to read identity credential: {}", e.getMessage());
            throw new SludiException(ErrorCodes.CREDENTIAL_NOT_FOUND, e);
        }
    }

    /**
     * Get all credentials for a specific DID
     */
    public List<VerifiableCredential> getCredentialsByDID(String subjectDID) {
        try {
            log.info("Getting credentials for DID: {}", subjectDID);

            byte[] result = contract.evaluateTransaction("GetCredentialsBySubject", subjectDID);
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
            log.error("Failed to get credentials: {}", e.getMessage());
            throw new SludiException(ErrorCodes.CREDENTIAL_RETRIEVAL_FAILED, e);
        }
    }

    /**
     * Update DID document on blockchain
     */
    public void updateDID(String didId, String publicKeysJson, String servicesJson, ProofData proof) {
        try {
            log.info("Updating DID: {}", didId);

            String proofJson = objectMapper.writeValueAsString(proof);

            contract.submitTransaction(
                    "UpdateDID",
                    didId,
                    publicKeysJson,
                    servicesJson,
                    proofJson
            );

            log.info("Successfully updated DID: {}", didId);

        } catch (Exception e) {
            log.error("Failed to update DID: {}", e.getMessage());
            throw new SludiException(ErrorCodes.DID_UPDATE_FAILED, e);
        }
    }

    /**
     * Deactivate DID document
     */
    public void deactivateDID(String didId) {
        try {
            log.info("Deactivating DID: {}", didId);

            contract.submitTransaction("DeactivateDID", didId);

            log.info("Successfully deactivated DID: {}", didId);

        } catch (Exception e) {
            log.error("Failed to deactivate DID: {}", e.getMessage());
            throw new SludiException(ErrorCodes.DID_DEACTIVATION_FAILED, e);
        }
    }

    /**
     * Delete a DID document from the ledger
     */
    public void deleteDID(String didId) {
        try {
            log.info("Deleting DID: {}", didId);

            contract.submitTransaction("DeleteDID", didId);

            log.info("Successfully deleted DID: {}", didId);

        } catch (Exception e) {
            log.error("Failed to delete DID: {}", e.getMessage());
            throw new SludiException(ErrorCodes.DID_DELETION_FAILED, e);
        }
    }

    /**
     * Check if DID exist on blockchain
     */
    public boolean didExists(String didId) {
        try {
            byte[] result = contract.evaluateTransaction("DIDExists", didId);
            String resultStr = new String(result);
            // Handle different return formats
            if (resultStr.equalsIgnoreCase("true") || resultStr.equals("1")) {
                return true;
            }
            return false;

        } catch (Exception e) {
            log.error("Failed to check DID existence: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Initialize the blockchain ledger
     */
    public void initializeLedger() {
        try {
            log.info("Initializing blockchain ledger");

            contract.submitTransaction("InitLedger");

            log.info("Successfully initialized blockchain ledger");

        } catch (Exception e) {
            log.error("Failed to initialize ledger: {}", e.getMessage());
            throw new SludiException(ErrorCodes.LEDGER_INITIALIZATION_FAILED, e);
        }
    }

    /**
     * Get system statistics from blockchain
     */
    public SystemStatsDto getSystemStats() {
        try {
            log.info("Getting system statistics");

            byte[] result = contract.evaluateTransaction("GetSystemStats");
            String statsJson = new String(result);
            SystemStatsDto stats = objectMapper.readValue(statsJson, SystemStatsDto.class);

            log.info("Successfully retrieved system statistics");
            return stats;

        } catch (Exception e) {
            log.error("Failed to get system statistics: {}", e.getMessage());
            throw new SludiException(ErrorCodes.SYSTEM_STATS_FAILED, e);
        }
    }

    /**
     * Get authentication logs for a user
     */
    public List<AuthenticationLog> getAuthenticationLogs(String userDID) {
        try {
            log.info("Getting authentication logs for DID: {}", userDID);

            byte[] result = contract.evaluateTransaction("GetAuthenticationLogs", userDID);
            String logsJson = new String(result);

            List<AuthenticationLog> logs = objectMapper.readValue(
                    logsJson,
                    new TypeReference<List<AuthenticationLog>>() {}
            );

            log.info("Found {} authentication logs for DID: {}", logs.size(), userDID);
            return logs;

        } catch (Exception e) {
            log.error("Failed to get authentication logs: {}", e.getMessage());
            throw new SludiException(ErrorCodes.AUTH_LOG_RETRIEVAL_FAILED, e);
        }
    }

    /**
     * Get all DIDs from blockchain (admin function)
     */
    public List<DIDDocumentDto> getAllDIDs() {
        try {
            log.info("Getting all DIDs from blockchain");

            byte[] result = contract.evaluateTransaction("GetAllDIDs");
            String didsJson = new String(result);

            List<DIDDocumentDto> dids = objectMapper.readValue(
                    didsJson,
                    new TypeReference<List<DIDDocumentDto>>() {}
            );

            log.info("Found " + dids.size() + " DIDs on blockchain");
            return dids;

        } catch (Exception e) {
            log.error("Failed to get all DIDs: {}", e.getMessage());
            throw new SludiException(ErrorCodes.DID_RETRIEVAL_FAILED, e);
        }
    }

    /**
     * Get all credentials from blockchain (admin function)
     */
    public List<VCBlockChainResult> getAllCredentials() {
        try {
            log.info("Getting all credentials from blockchain");

            byte[] result = contract.evaluateTransaction("GetAllCredentials");
            String credentialsJson = new String(result);

            List<VCBlockChainResult> credentials = objectMapper.readValue(
                    credentialsJson,
                    new TypeReference<List<VCBlockChainResult>>() {}
            );

            log.info("Found {} credentials on blockchain", credentials.size());
            return credentials;

        } catch (Exception e) {
            log.error("Failed to get all credentials: {}", e.getMessage());
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
            log.error("Blockchain health check failed: {}", e.getMessage());
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
            log.error("Failed to get network info: {}", e.getMessage());
            return BlockchainNetworkInfo.builder()
                    .networkName("SLUDI-Network")
                    .status("UNHEALTHY")
                    .lastUpdated(Instant.now().toString())
                    .build();
        }
    }

    /**
     * Registers a user on the blockchain ledger for a given organization MSP.
     */
    public String registerUserOnBlockchain(OrganizationUser user, String mspId) throws Exception {
        log.info("Registering user on blockchain ledger: {}", user.getFabricUserId());

        String permissionsJson = objectMapper.writeValueAsString(
                user.getAssignedRole().getPermissions()
        );

        byte[] result = contract.submitTransaction(
                "RegisterOrganizationUser",
                user.getFabricUserId(),
                user.getEmployeeId(),
                user.getUsername(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.getOrganization().getOrgCode(),
                user.getOrganization().getName(),
                mspId,
                user.getAssignedRole().getRoleCode(),
                permissionsJson,
                user.getDepartment(),
                user.getDesignation()
        );

        // Read ledger response - RegisterOrganizationUser returns JSON with txId
        String txResponse = new String(result, StandardCharsets.UTF_8);
        Map<String, Object> txInfo = objectMapper.readValue(txResponse, Map.class);

        log.info("User successfully registered on blockchain: {}", txResponse);

        return (String) txInfo.get("txId");
    }

    /**
     * Update user role on blockchain
     */
    public String updateUserRoleOnBlockchain(OrganizationUser user) throws Exception {
        log.info("Updating user role on blockchain: {}", user.getFabricUserId());

        Map<String, Object> updateData = new HashMap<>();
        updateData.put("fabricUserId", user.getFabricUserId());
        updateData.put("newRoleCode", user.getAssignedRole().getRoleCode());
        updateData.put("newPermissions", user.getAssignedRole().getPermissions());

        byte[] result = contract.submitTransaction(
                "UpdateUserRole",
                gson.toJson(updateData)
        );

        String resultString = new String(result);
        Map<String, Object> txInfo = objectMapper.readValue(resultString, Map.class);
        return (String) txInfo.get("txId");
    }

    /**
     * Revoke user access on blockchain
     */
    public String revokeUserAccessOnBlockchain(OrganizationUser user, String reason)
            throws Exception {
        log.info("Revoking user access on blockchain: {}", user.getFabricUserId());

        Map<String, Object> revokeData = new HashMap<>();
        revokeData.put("fabricUserId", user.getFabricUserId());
        revokeData.put("reason", reason);

        byte[] result = contract.submitTransaction(
                "RevokeUserAccess",
                gson.toJson(revokeData)
        );

        String resultString = new String(result);
        Map<String, Object> txInfo = objectMapper.readValue(resultString, Map.class);
        return (String) txInfo.get("txId");
    }

    /**
     * Restore user access on blockchain
     */
    public String restoreUserAccessOnBlockchain(OrganizationUser user) throws Exception {
        log.info("Restoring user access on blockchain: {}", user.getFabricUserId());

        Map<String, Object> restoreData = new HashMap<>();
        restoreData.put("fabricUserId", user.getFabricUserId());

        byte[] result = contract.submitTransaction(
                "RestoreUserAccess",
                gson.toJson(restoreData)
        );

        String resultString = new String(result);
        Map<String, Object> txInfo = objectMapper.readValue(resultString, Map.class);
        return (String) txInfo.get("txId");
    }

    /**
     * Update user permissions on blockchain
     */
    public void updateUserPermissionsOnBlockchain(OrganizationUser user) throws Exception {
        // Calculate effective permissions
        List<String> effectivePermissions = new ArrayList<>(
                user.getAssignedRole().getPermissions()
        );

        Map<String, Object> updateData = new HashMap<>();
        updateData.put("fabricUserId", user.getFabricUserId());
        updateData.put("permissions", effectivePermissions);

        contract.submitTransaction(
                "UpdateUserPermissions",
                gson.toJson(updateData)
        );
    }

    /**
     * Close gateway connection (for cleanup)
     */
    public void closeConnection() {
        try {
            if (gateway != null) {
                gateway.close();
                log.info("Gateway connection closed successfully");
            }
        } catch (Exception e) {
            log.error("Failed to close gateway connection: {}", e.getMessage());
        }
    }
}