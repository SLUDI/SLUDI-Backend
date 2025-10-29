package org.example.integration;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.example.dto.*;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.security.CryptographyService;

import io.ipfs.api.IPFS;
import io.ipfs.api.MerkleNode;
import io.ipfs.api.NamedStreamable;
import io.ipfs.multihash.Multihash;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

@Service
public class IPFSIntegration {

    private static final Logger LOGGER = Logger.getLogger(IPFSIntegration.class.getName());

    @Value("${ipfs.api.host}")
    private String ipfsHost;

    @Value("${ipfs.api.port}")
    private int ipfsPort;

    @Value("${ipfs.gateway.url}")
    private String ipfsGatewayUrl;

    @Value("${sludi.ipfs.encryption.enabled}")
    private boolean encryptionEnabled;

    @Value("${sludi.ipfs.pin.enabled}")
    private boolean pinningEnabled;

    @Value("${sludi.ipfs.timeout.seconds}")
    private int timeoutSeconds;

    @Value("${sludi.ipfs.retry.attempts}")
    private int retryAttempts;

    private final CryptographyService cryptographyService;

    private IPFS ipfs;
    private Map<String, String> hashPathCache;
    private Map<String, Long> fileSizeCache;

    public IPFSIntegration(CryptographyService cryptographyService) {
        this.cryptographyService = cryptographyService;
    }

    /**
     * Initialize IPFS service
     */
    @PostConstruct
    public void initialize() {
        try {
            LOGGER.info("Initializing IPFS service with host: " + ipfsHost + ":" + ipfsPort);

            ipfs = new IPFS(ipfsHost, ipfsPort);
            hashPathCache = new ConcurrentHashMap<>();
            fileSizeCache = new ConcurrentHashMap<>();

            // Test IPFS connection
            testConnection();

            LOGGER.info("IPFS service initialized successfully");

        } catch (Exception e) {
            LOGGER.severe("Failed to initialize IPFS service: " + e.getMessage());
            throw new SludiException(ErrorCodes.IPFS_INITIALIZATION_FAILED, e);
        }
    }

    /**
     * Cleanup resources on shutdown
     */
    @PreDestroy
    public void cleanup() {
        try {
            if (ipfs != null) {
                // Cleanup any resources if needed
                LOGGER.info("IPFS service cleanup completed");
            }
        } catch (Exception e) {
            LOGGER.warning("Error during IPFS cleanup: " + e.getMessage());
        }
    }

    /**
     * Store file content in IPFS with optional encryption
     * @param path Path where the file will be stored in IPFS
     * @param content byte[] content of the file
     * @return IPFS hash of the stored file
     * @throws SludiException if storage fails or encryption fails
     */
    public String storeFile(String path, byte[] content) {
        return storeFileWithRetry(path, content, retryAttempts);
    }

    /**
     * Store file from MultipartFile
     * @param path Path where the file will be stored in IPFS
     * @param file MultipartFile to store
     * @return IPFS hash of the stored file
     * @throws SludiException if file reading fails
     */
    public String storeFile(String path, MultipartFile file) {
        try {
            byte[] content = file.getBytes();
            return storeFile(path, content);
        } catch (IOException e) {
            throw new SludiException(ErrorCodes.FILE_READ_ERROR, e);
        }
    }

    /**
     * Retrieve file content from IPFS with optional decryption
     * @param ipfsHash
     * @return byte[] content of the file
     * @throws SludiException if file retrieval fails or content is empty
     */
    public byte[] retrieveFile(String ipfsHash) {
        return retrieveFileWithRetry(ipfsHash, retryAttempts);
    }

    /**
     * Retrieve file as string (for text content)
     * @param ipfsHash
     * @return String content of the file
     * @throws SludiException if file retrieval fails or content is not valid UTF-8
     */
    public String retrieveFileAsString(String ipfsHash) {
        byte[] content = retrieveFile(ipfsHash);
        return new String(content, StandardCharsets.UTF_8);
    }

    /**
     * Store JSON data as file
     * @param path Path where the JSON file will be stored
     * @param data Object to serialize to JSON
     * @return IPFS hash of the stored JSON file
     * @throws SludiException if serialization fails
     */
    public String storeJsonData(String path, Object data) {
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper =
                    new com.fasterxml.jackson.databind.ObjectMapper();
            String jsonContent = mapper.writeValueAsString(data);
            return storeFile(path, jsonContent.getBytes(StandardCharsets.UTF_8));

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.JSON_SERIALIZATION_FAILED, e);
        }
    }

    /**
     * Retrieve and deserialize JSON data
     * @param ipfsHash
     * @param targetClass Class to deserialize into
     * @param <T> Type of the target class
     * @return Deserialized object of type T
     * @throws SludiException if deserialization fails
     */
    public <T> T retrieveJsonData(String ipfsHash, Class<T> targetClass) {
        try {
            String jsonContent = retrieveFileAsString(ipfsHash);
            com.fasterxml.jackson.databind.ObjectMapper mapper =
                    new com.fasterxml.jackson.databind.ObjectMapper();
            return mapper.readValue(jsonContent, targetClass);

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.JSON_DESERIALIZATION_FAILED, e);
        }
    }

    /**
     * Store encrypted biometric data
     * @param userId
     * @param biometricType
     * @param biometricData
     * @return IPFS hash of the stored biometric data
     * @throws SludiException if storage fails or encryption fails
     */
    public String storeBiometricData(String userId, String biometricType, byte[] biometricData) {
        try {
            LOGGER.info("Storing biometric data for user: " + userId + ", type: " + biometricType);

            // Create metadata
            BiometricMetadata metadata = BiometricMetadata.builder()
                    .userId(userId)
                    .biometricType(biometricType)
                    .timestamp(System.currentTimeMillis())
                    .originalSize(biometricData.length)
                    .encrypted(encryptionEnabled)
                    .build();

            // Encrypt biometric data if encryption is enabled
            byte[] processedData = encryptionEnabled ?
                    cryptographyService.encryptBiometricData(biometricData) : biometricData;

            // Create container with metadata and data
            BiometricContainer container = BiometricContainer.builder()
                    .metadata(metadata)
                    .data(Base64.getEncoder().encodeToString(processedData))
                    .checksum(generateChecksum(biometricData))
                    .build();

            // Store container as JSON
            String path = String.format("biometric/users/%s/%s/data_%d.json",
                    userId, biometricType, System.currentTimeMillis());

            return storeJsonData(path, container);

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.BIOMETRIC_STORAGE_FAILED, e);
        }
    }

    /**
     * Retrieve and decrypt biometric data
     * @param ipfsHash
     * @param expectedUserId
     * @return byte[] containing the original biometric data
     * @throws SludiException if access is denied or data integrity check fails
     */
    public byte[] retrieveBiometricData(String ipfsHash, String expectedUserId) {
        try {
            LOGGER.info("Retrieving biometric data from hash: " + ipfsHash);

            // Retrieve container
            BiometricContainer container = retrieveJsonData(ipfsHash, BiometricContainer.class);

            // Verify user ID matches (security check)
            if (!expectedUserId.equals(container.getMetadata().getUserId())) {
                throw new SludiException(ErrorCodes.BIOMETRIC_ACCESS_DENIED);
            }

            // Decode base64 data
            byte[] processedData = Base64.getDecoder().decode(container.getData());

            // Decrypt if data was encrypted
            byte[] originalData = container.getMetadata().isEncrypted() ?
                    cryptographyService.decryptBiometricData(processedData) : processedData;

            // Verify checksum
            String expectedChecksum = generateChecksum(originalData);
            if (!expectedChecksum.equals(container.getChecksum())) {
                throw new SludiException(ErrorCodes.DATA_INTEGRITY_FAILED);
            }

            LOGGER.info("Successfully retrieved and verified biometric data");
            return originalData;

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.BIOMETRIC_RETRIEVAL_ERROR, e);
        }
    }

    /**
     * Store user document with metadata
     * @param userId
     * @param documentType
     * @param documentData
     * @param fileName
     * @param mimeType
     * @return DocumentStorageResult containing document hash and metadata hash
     * @throws SludiException if storage fails or access is denied
     */
    public DocumentStorageResult storeUserDocument(String userId, String documentType,
                                                   byte[] documentData, String fileName,
                                                   String mimeType) {
        try {
            LOGGER.info("Storing document for user: " + userId + ", type: " + documentType);

            // Create document metadata
            DocumentMetadata metadata = DocumentMetadata.builder()
                    .userId(userId)
                    .documentType(documentType)
                    .fileName(fileName)
                    .mimeType(mimeType)
                    .fileSize(documentData.length)
                    .uploadTimestamp(System.currentTimeMillis())
                    .encrypted(encryptionEnabled)
                    .build();

            // Encrypt document if encryption is enabled
            byte[] processedData = encryptionEnabled ?
                    cryptographyService.encrypt(Base64.getEncoder().encodeToString(documentData))
                            .getBytes(StandardCharsets.UTF_8) : documentData;

            // Store document data
            String documentPath = String.format("documents/users/%s/%s/%s",
                    userId, documentType, fileName);
            String documentHash = storeFile(documentPath, processedData);

            // Store metadata separately
            String metadataPath = String.format("documents/users/%s/%s/metadata_%s.json",
                    userId, documentType, System.currentTimeMillis());
            String metadataHash = storeJsonData(metadataPath, metadata);

            // Pin important files
            if (pinningEnabled) {
                pinFile(documentHash);
                pinFile(metadataHash);
            }

            return DocumentStorageResult.builder()
                    .documentHash(documentHash)
                    .metadataHash(metadataHash)
                    .fileSize(documentData.length)
                    .encrypted(encryptionEnabled)
                    .success(true)
                    .build();

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.DOCUMENT_STORAGE_ERROR, e);
        }
    }

    /**
     * Retrieve user document with verification
     * @param documentHash
     * @param metadataHash
     * @param expectedUserId
     * @return DocumentRetrievalResult containing document data and metadata
     * @throws SludiException if access is denied or retrieval fails
     */
    public DocumentRetrievalResult retrieveUserDocument(String documentHash, String metadataHash,
                                                        String expectedUserId) {
        try {
            LOGGER.info("Retrieving document with hash: " + documentHash);

            // Retrieve metadata first
            DocumentMetadata metadata = retrieveJsonData(metadataHash, DocumentMetadata.class);

            // Verify user access
            if (!expectedUserId.equals(metadata.getUserId())) {
                throw new SludiException(ErrorCodes.DOCUMENT_ACCESS_DENIED);
            }

            // Retrieve document data
            byte[] processedData = retrieveFile(documentHash);

            // Decrypt if data was encrypted
            byte[] originalData;
            if (metadata.isEncrypted()) {
                String decryptedString = cryptographyService.decrypt(
                        new String(processedData, StandardCharsets.UTF_8));
                originalData = Base64.getDecoder().decode(decryptedString);
            } else {
                originalData = processedData;
            }

            return DocumentRetrievalResult.builder()
                    .documentData(originalData)
                    .metadata(metadata)
                    .success(true)
                    .build();

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.DOCUMENT_RETRIEVAL_FAILED, e);
        }
    }

    /**
     * Store multiple files in batch
     * @param filesData Map of file paths to their byte content
     * @return Map with file paths and their IPFS hashes or error messages
     */
    public Map<String, String> storeFilesBatch(Map<String, byte[]> filesData) {
        Map<String, String> results = new HashMap<>();

        List<CompletableFuture<Void>> futures = new ArrayList<>();

        for (Map.Entry<String, byte[]> entry : filesData.entrySet()) {
            CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                try {
                    String hash = storeFile(entry.getKey(), entry.getValue());
                    synchronized (results) {
                        results.put(entry.getKey(), hash);
                    }
                } catch (Exception e) {
                    LOGGER.warning("Failed to store file in batch: " + entry.getKey());
                    synchronized (results) {
                        results.put(entry.getKey(), "ERROR: " + e.getMessage());
                    }
                }
            });
            futures.add(future);
        }

        // Wait for all operations to complete
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .orTimeout(timeoutSeconds * 2, TimeUnit.SECONDS)
                .join();

        return results;
    }

    /**
     * Retrieve multiple files in batch
     * @param ipfsHashes
     * @return Map with file hashes and their content
     */
    public Map<String, byte[]> retrieveFilesBatch(List<String> ipfsHashes) {
        Map<String, byte[]> results = new HashMap<>();

        List<CompletableFuture<Void>> futures = new ArrayList<>();

        for (String hash : ipfsHashes) {
            CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                try {
                    byte[] data = retrieveFile(hash);
                    synchronized (results) {
                        results.put(hash, data);
                    }
                } catch (Exception e) {
                    LOGGER.warning("Failed to retrieve file in batch: " + hash);
                    synchronized (results) {
                        results.put(hash, null);
                    }
                }
            });
            futures.add(future);
        }

        // Wait for all operations to complete
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .orTimeout(timeoutSeconds * 2, TimeUnit.SECONDS)
                .join();

        return results;
    }


    /**
     * Pin file to keep it in IPFS network
     * @param ipfsHash
     * This method ensures the file remains available in the IPFS network.
     */
    public void pinFile(String ipfsHash) {
        try {
            if (pinningEnabled) {
                Multihash multihash = Multihash.fromBase58(ipfsHash);
                ipfs.pin.add(multihash);
                LOGGER.info("Pinned file: " + ipfsHash);
            }
        } catch (Exception e) {
            LOGGER.warning("Failed to pin file: " + ipfsHash + " - " + e.getMessage());
        }
    }

    /**
     * Unpin file from IPFS network
     * @param ipfsHash
     */
    public void unpinFile(String ipfsHash) {
        try {
            Multihash multihash = Multihash.fromBase58(ipfsHash);
            ipfs.pin.rm(multihash);
            LOGGER.info("Unpinned file: " + ipfsHash);
        } catch (Exception e) {
            LOGGER.warning("Failed to unpin file: " + ipfsHash + " - " + e.getMessage());
        }
    }

    /**
     * Get file information without downloading
     * @param ipfsHash
     * @return IPFSFileInfo with file details
     */
    public IPFSFileInfo getFileInfo(String ipfsHash) {
        try {
            Multihash multihash = Multihash.fromBase58(ipfsHash);
            Map<String, Object> stat = ipfs.object.stat(multihash);

            return IPFSFileInfo.builder()
                    .hash(ipfsHash)
                    .size(Long.parseLong(stat.get("CumulativeSize").toString()))
                    .type(stat.get("Type").toString())
                    .exists(true)
                    .build();

        } catch (Exception e) {
            LOGGER.warning("Failed to get file info: " + ipfsHash + " -> " + e.getMessage());
            return IPFSFileInfo.builder()
                    .hash(ipfsHash)
                    .exists(false)
                    .build();
        }
    }

    /**
     * Check if file exists in IPFS
     * @param ipfsHash
     */
    public boolean fileExists(String ipfsHash) {
        return getFileInfo(ipfsHash).isExists();
    }

    /**
     * Get IPFS node info
     * @return Map with node information
     * @throws SludiException if connection fails
     */
    @SuppressWarnings("unchecked")
    public Map<String, String> getNodeInfo() {
        try {
            return (Map<String, String>) ipfs.id();
        } catch (IOException e) {
            throw new SludiException(ErrorCodes.IPFS_CONNECTION_FAILED, e);
        }
    }

    /**
     * Store file with retry logic
     * @param path
     * @param content
     * @param attemptsLeft
     * @return
     */
    private String storeFileWithRetry(String path, byte[] content, int attemptsLeft) {
        try {
            LOGGER.info("Storing file: " + path + " (size: " + content.length + " bytes)");

            // Create named streamable for the content
            NamedStreamable.ByteArrayWrapper wrapper =
                    new NamedStreamable.ByteArrayWrapper(path, content);

            // Add file to IPFS
            List<MerkleNode> result = ipfs.add(wrapper);

            if (result.isEmpty()) {
                throw new SludiException(ErrorCodes.IPFS_STORAGE_FAILED, path);
            }

            String hash = result.get(0).hash.toBase58();

            // Cache the mapping
            hashPathCache.put(hash, path);
            fileSizeCache.put(hash, (long) content.length);

            // Pin file if pinning is enabled
            if (pinningEnabled) {
                pinFile(hash);
            }

            LOGGER.info("Successfully stored file: " + path + " with hash: " + hash);
            return hash;

        } catch (Exception e) {
            if (attemptsLeft > 1) {
                LOGGER.warning("Failed to store file, retrying. Attempts left: " + (attemptsLeft - 1));
                try {
                    Thread.sleep(1000); // Wait 1 second before retry
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
                return storeFileWithRetry(path, content, attemptsLeft - 1);
            } else {
                LOGGER.severe("Failed to store file after all retry attempts: " + path);
                throw new SludiException(ErrorCodes.IPFS_STORAGE_FAILED,
                        "Failed to store file in IPFS: " + path, e);
            }
        }
    }

    /**
     * Retrieve file with retry logic
     * @param ipfsHash
     * @param attemptsLeft
     * @return
     */
    private byte[] retrieveFileWithRetry(String ipfsHash, int attemptsLeft) {
        try {
            LOGGER.info("Retrieving file with hash: " + ipfsHash);

            Multihash multihash = Multihash.fromBase58(ipfsHash);
            byte[] content = ipfs.cat(multihash);

            if (content == null || content.length == 0) {
                throw new SludiException(ErrorCodes.IPFS_FILE_NOT_FOUND, ipfsHash);
            }

            LOGGER.info("Successfully retrieved file: " + ipfsHash + " (size: " + content.length + " bytes)");
            return content;

        } catch (Exception e) {
            if (attemptsLeft > 1) {
                LOGGER.warning("Failed to retrieve file, retrying. Attempts left: " + (attemptsLeft - 1));
                try {
                    Thread.sleep(1000); // Wait 1 second before retry
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
                return retrieveFileWithRetry(ipfsHash, attemptsLeft - 1);
            } else {
                LOGGER.severe("Failed to retrieve file after all retry attempts: " + ipfsHash);
                throw new SludiException(ErrorCodes.IPFS_RETRIEVAL_FAILED, ipfsHash, e);
            }
        }
    }

    /**
     * Test IPFS connection by retrieving node info
     */
    private void testConnection() {
        try {
            Map<String, Object> nodeInfo = ipfs.id();
            LOGGER.info("IPFS connection successful. Node ID: " + nodeInfo.get("ID"));
        } catch (Exception e) {
            throw new SludiException(ErrorCodes.IPFS_CONNECTION_FAILED,
                    "Failed to connect to IPFS node", e);
        }
    }

    /**
     * Generate SHA-256 checksum for data
     * @param data
     * @return Base64 encoded checksum
     */
    private String generateChecksum(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new SludiException(ErrorCodes.CHECKSUM_GENERATION_FAILED, e);
        }
    }
}