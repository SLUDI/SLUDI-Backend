package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.entity.*;
import org.example.enums.EntityType;
import org.example.enums.SyncStatus;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.*;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Service
public class BlockchainSyncService {

    private final HyperledgerService hyperledgerService;
    private final DIDDocumentRepository didDocumentRepository;
    private final VerifiableCredentialRepository verifiableCredentialRepository;
    private final SyncMetadataRepository syncMetadataRepository;
    private final PublicKeyRepository publicKeyRepository;
    private final ObjectMapper objectMapper;

    private static final int MAX_RETRY_COUNT = 3;
    private static final int SYNC_BATCH_SIZE = 50;

    public BlockchainSyncService(
            HyperledgerService hyperledgerService,
            DIDDocumentRepository didDocumentRepository,
            VerifiableCredentialRepository verifiableCredentialRepository,
            SyncMetadataRepository syncMetadataRepository,
            PublicKeyRepository publicKeyRepository,
            ObjectMapper objectMapper) {
        this.hyperledgerService = hyperledgerService;
        this.didDocumentRepository = didDocumentRepository;
        this.verifiableCredentialRepository = verifiableCredentialRepository;
        this.syncMetadataRepository = syncMetadataRepository;
        this.publicKeyRepository = publicKeyRepository;
        this.objectMapper = objectMapper;
    }

    /**
     * Sync a single DID from blockchain to PostgreSQL
     */
    @Transactional
    public SyncStatusDto syncDIDFromBlockchain(String didId) {
        log.info("Starting sync for DID: {}", didId);
        LocalDateTime startTime = LocalDateTime.now();

        try {
            // Fetch DID from blockchain
            DIDDocumentDto blockchainDID = hyperledgerService.getDIDDocument(didId);

            if (blockchainDID == null) {
                throw new SludiException(ErrorCodes.DID_NOT_FOUND, didId);
            }

            // Convert DTO to Entity
            DIDDocument didDocument = convertDIDDtoToEntity(blockchainDID);

            // Save or update in PostgreSQL
            didDocumentRepository.save(didDocument);

            // Update sync metadata
            SyncMetadata syncMetadata = createOrUpdateSyncMetadata(
                    EntityType.DID.name(),
                    didId,
                    blockchainDID.getBlockchainTxId(),
                    blockchainDID.getBlockNumber(),
                    SyncStatus.SYNCED.name(),
                    null);

            log.info("Successfully synced DID: {} in {} ms", didId,
                    Duration.between(startTime, LocalDateTime.now()).toMillis());

            return convertSyncMetadataToDto(syncMetadata);

        } catch (Exception e) {
            log.error("Failed to sync DID {}: {}", didId, e.getMessage(), e);

            // Update sync metadata with error
            SyncMetadata syncMetadata = createOrUpdateSyncMetadata(
                    EntityType.DID.name(),
                    didId,
                    null,
                    null,
                    SyncStatus.FAILED.name(),
                    e.getMessage());

            return convertSyncMetadataToDto(syncMetadata);
        }
    }

    /**
     * Sync a single Verifiable Credential from blockchain to PostgreSQL
     */
    @Transactional
    public SyncStatusDto syncCredentialFromBlockchain(String credentialId) {
        log.info("Starting sync for Credential: {}", credentialId);
        LocalDateTime startTime = LocalDateTime.now();

        try {
            // Fetch credential from blockchain
            VCBlockChainResult blockchainVC = hyperledgerService.readCredential(credentialId);

            if (blockchainVC == null) {
                throw new SludiException(ErrorCodes.CREDENTIAL_NOT_FOUND, credentialId);
            }

            // Convert to Entity
            VerifiableCredential credential = convertVCDtoToEntity(blockchainVC);

            // Save or update in PostgreSQL
            verifiableCredentialRepository.save(credential);

            // Update sync metadata
            SyncMetadata syncMetadata = createOrUpdateSyncMetadata(
                    EntityType.VERIFIABLE_CREDENTIAL.name(),
                    credentialId,
                    blockchainVC.getBlockchainTxId(),
                    blockchainVC.getBlockNumber(),
                    SyncStatus.SYNCED.name(),
                    null);

            log.info("Successfully synced Credential: {} in {} ms", credentialId,
                    Duration.between(startTime, LocalDateTime.now()).toMillis());

            return convertSyncMetadataToDto(syncMetadata);

        } catch (Exception e) {
            log.error("Failed to sync Credential {}: {}", credentialId, e.getMessage(), e);

            // Update sync metadata with error
            SyncMetadata syncMetadata = createOrUpdateSyncMetadata(
                    EntityType.VERIFIABLE_CREDENTIAL.name(),
                    credentialId,
                    null,
                    null,
                    SyncStatus.FAILED.name(),
                    e.getMessage());

            return convertSyncMetadataToDto(syncMetadata);
        }
    }

    /**
     * Sync all DIDs from blockchain to PostgreSQL
     */
    @Transactional
    public SyncReportDto syncAllDIDs() {
        log.info("Starting full DID synchronization");
        LocalDateTime startTime = LocalDateTime.now();

        try {
            // Get all DIDs from blockchain
            List<DIDDocumentDto> blockchainDIDs = hyperledgerService.getAllDIDs();

            int syncedCount = 0;
            int failedCount = 0;
            List<SyncStatusDto> failedSyncs = new ArrayList<>();

            for (DIDDocumentDto didDto : blockchainDIDs) {
                try {
                    SyncStatusDto status = syncDIDFromBlockchain(didDto.getId());
                    if (SyncStatus.SYNCED.name().equals(status.getSyncStatus())) {
                        syncedCount++;
                    } else {
                        failedCount++;
                        failedSyncs.add(status);
                    }
                } catch (Exception e) {
                    log.error("Error syncing DID {}: {}", didDto.getId(), e.getMessage());
                    failedCount++;
                }
            }

            String duration = Duration.between(startTime, LocalDateTime.now()).toSeconds() + " seconds";

            return SyncReportDto.builder()
                    .totalEntities(blockchainDIDs.size())
                    .syncedCount(syncedCount)
                    .failedCount(failedCount)
                    .pendingCount(0)
                    .failedSyncs(failedSyncs)
                    .syncDuration(duration)
                    .build();

        } catch (Exception e) {
            log.error("Failed to sync all DIDs: {}", e.getMessage(), e);
            throw new SludiException(ErrorCodes.SYNC_FAILED, e);
        }
    }

    /**
     * Sync all Verifiable Credentials from blockchain to PostgreSQL
     */
    @Transactional
    public SyncReportDto syncAllCredentials() {
        log.info("Starting full Credential synchronization");
        LocalDateTime startTime = LocalDateTime.now();

        try {
            // Get all credentials from blockchain
            List<VCBlockChainResult> blockchainVCs = hyperledgerService.getAllCredentials();

            int syncedCount = 0;
            int failedCount = 0;
            List<SyncStatusDto> failedSyncs = new ArrayList<>();

            for (VCBlockChainResult vcDto : blockchainVCs) {
                try {
                    SyncStatusDto status = syncCredentialFromBlockchain(vcDto.getId());
                    if (SyncStatus.SYNCED.name().equals(status.getSyncStatus())) {
                        syncedCount++;
                    } else {
                        failedCount++;
                        failedSyncs.add(status);
                    }
                } catch (Exception e) {
                    log.error("Error syncing Credential {}: {}", vcDto.getId(), e.getMessage());
                    failedCount++;
                }
            }

            String duration = Duration.between(startTime, LocalDateTime.now()).toSeconds() + " seconds";

            return SyncReportDto.builder()
                    .totalEntities(blockchainVCs.size())
                    .syncedCount(syncedCount)
                    .failedCount(failedCount)
                    .pendingCount(0)
                    .failedSyncs(failedSyncs)
                    .syncDuration(duration)
                    .build();

        } catch (Exception e) {
            log.error("Failed to sync all Credentials: {}", e.getMessage(), e);
            throw new SludiException(ErrorCodes.SYNC_FAILED, e);
        }
    }

    /**
     * Retry failed synchronizations
     */
    @Transactional
    public SyncReportDto retryFailedSyncs() {
        log.info("Retrying failed synchronizations");
        LocalDateTime startTime = LocalDateTime.now();

        List<SyncMetadata> failedSyncs = syncMetadataRepository
                .findBySyncStatusAndRetryCountLessThan(SyncStatus.FAILED.name(), MAX_RETRY_COUNT);

        int syncedCount = 0;
        int failedCount = 0;
        List<SyncStatusDto> stillFailed = new ArrayList<>();

        for (SyncMetadata metadata : failedSyncs) {
            try {
                SyncStatusDto status;
                if (EntityType.DID.name().equals(metadata.getEntityType())) {
                    status = syncDIDFromBlockchain(metadata.getEntityId());
                } else {
                    status = syncCredentialFromBlockchain(metadata.getEntityId());
                }

                if (SyncStatus.SYNCED.name().equals(status.getSyncStatus())) {
                    syncedCount++;
                } else {
                    failedCount++;
                    stillFailed.add(status);
                }
            } catch (Exception e) {
                log.error("Retry failed for {} {}: {}",
                        metadata.getEntityType(), metadata.getEntityId(), e.getMessage());
                failedCount++;
            }
        }

        String duration = Duration.between(startTime, LocalDateTime.now()).toSeconds() + " seconds";

        return SyncReportDto.builder()
                .totalEntities(failedSyncs.size())
                .syncedCount(syncedCount)
                .failedCount(failedCount)
                .pendingCount(0)
                .failedSyncs(stillFailed)
                .syncDuration(duration)
                .build();
    }

    /**
     * Get sync status for a specific entity
     */
    public SyncStatusDto getSyncStatus(String entityType, String entityId) {
        Optional<SyncMetadata> metadata = syncMetadataRepository
                .findByEntityTypeAndEntityId(entityType, entityId);

        return metadata.map(this::convertSyncMetadataToDto)
                .orElse(SyncStatusDto.builder()
                        .entityType(entityType)
                        .entityId(entityId)
                        .syncStatus(SyncStatus.PENDING.name())
                        .build());
    }

    /**
     * Get all sync statuses
     */
    public List<SyncStatusDto> getAllSyncStatuses() {
        return syncMetadataRepository.findAll().stream()
                .map(this::convertSyncMetadataToDto)
                .collect(Collectors.toList());
    }

    /**
     * Scheduled job to sync blockchain data every hour
     */
    @Scheduled(fixedRate = 3600000) // Run every hour
    @Async
    public void scheduledSync() {
        log.info("Starting scheduled blockchain synchronization");
        try {
            syncAllDIDs();
            syncAllCredentials();
            retryFailedSyncs();
            log.info("Scheduled synchronization completed successfully");
        } catch (Exception e) {
            log.error("Scheduled synchronization failed: {}", e.getMessage(), e);
        }
    }

    /**
     * Helper: Convert DIDDocumentDto to DIDDocument entity
     */
    private DIDDocument convertDIDDtoToEntity(DIDDocumentDto dto) {
        // Convert ProofDataDto to ProofData
        ProofData proofData = null;
        if (dto.getProof() != null) {
            proofData = ProofData.builder()
                    .proofType(dto.getProof().getProofType())
                    .created(dto.getProof().getCreated())
                    .creator(dto.getProof().getCreator())
                    .issuerDid(dto.getProof().getIssuerDid())
                    .signatureValue(dto.getProof().getSignatureValue())
                    .build();
        }

        DIDDocument entity = DIDDocument.builder()
                .id(dto.getId())
                .didVersion(dto.getDidVersion())
                .didCreated(dto.getDidCreated())
                .didUpdated(dto.getDidUpdated())
                .status(dto.getStatus())
                .proof(proofData)
                .blockchainTxId(dto.getBlockchainTxId())
                .blockNumber(dto.getBlockNumber())
                .build();

        // Handle public keys - use publicKeys field from DTO
        if (dto.getPublicKeys() != null && !dto.getPublicKeys().isEmpty()) {
            List<PublicKey> publicKeys = dto.getPublicKeys().stream()
                    .map(pkDto -> PublicKey.builder()
                            .id(pkDto.getId())
                            .type(pkDto.getType())
                            .controller(pkDto.getController())
                            .publicKeyBase58(pkDto.getPublicKeyBase58())
                            .didDocument(entity)
                            .build())
                    .collect(Collectors.toList());
            entity.setPublicKey(publicKeys);
        }

        // Handle authentication
        if (dto.getAuthentication() != null) {
            entity.setAuthentication(dto.getAuthentication());
        }

        // Handle services
        if (dto.getServices() != null && !dto.getServices().isEmpty()) {
            List<Services> services = dto.getServices().stream()
                    .map(svcDto -> Services.builder()
                            .id(svcDto.getId())
                            .type(svcDto.getType())
                            .serviceEndpoint(svcDto.getServiceEndpoint())
                            .didDocument(entity)
                            .build())
                    .collect(Collectors.toList());
            entity.setServices(services);
        }

        return entity;
    }

    /**
     * Helper: Convert VCBlockChainResult to VerifiableCredential entity
     */
    private VerifiableCredential convertVCDtoToEntity(VCBlockChainResult dto) {
        // Convert ProofDataDto to ProofData
        ProofData proofData = null;
        if (dto.getProof() != null) {
            proofData = ProofData.builder()
                    .proofType(dto.getProof().getProofType())
                    .created(dto.getProof().getCreated())
                    .creator(dto.getProof().getCreator())
                    .issuerDid(dto.getProof().getIssuerDid())
                    .signatureValue(dto.getProof().getSignatureValue())
                    .build();
        }

        VerifiableCredential entity = VerifiableCredential.builder()
                .id(dto.getId())
                .subjectDid(dto.getSubjectDID())
                .credentialType(dto.getCredentialType())
                .issuanceDate(dto.getIssuanceDate())
                .expirationDate(dto.getExpirationDate())
                .status(dto.getStatus())
                .proof(proofData)
                .blockchainTxId(dto.getBlockchainTxId())
                .blockNumber(dto.getBlockNumber())
                .credentialSubjectHash(dto.getCredentialSubjectHash())
                .build();

        // Note: VCBlockChainResult doesn't have claims field
        // Claims are stored separately and managed by the credential service
        // If you need to sync claims, you'll need to fetch them separately

        return entity;
    }

    /**
     * Helper: Create or update sync metadata
     */
    private SyncMetadata createOrUpdateSyncMetadata(
            String entityType,
            String entityId,
            String blockchainTxId,
            Long blockNumber,
            String syncStatus,
            String errorMessage) {

        Optional<SyncMetadata> existing = syncMetadataRepository
                .findByEntityTypeAndEntityId(entityType, entityId);

        SyncMetadata metadata;
        if (existing.isPresent()) {
            metadata = existing.get();
            metadata.setSyncStatus(syncStatus);
            metadata.setLastSyncedAt(LocalDateTime.now());
            metadata.setErrorMessage(errorMessage);

            if (SyncStatus.FAILED.name().equals(syncStatus)) {
                metadata.setRetryCount(
                        metadata.getRetryCount() != null ? metadata.getRetryCount() + 1 : 1
                );
            } else if (SyncStatus.SYNCED.name().equals(syncStatus)) {
                metadata.setRetryCount(0);
                metadata.setBlockchainTxId(blockchainTxId);
                metadata.setBlockNumber(blockNumber);
            }

        } else {
            metadata = SyncMetadata.builder()
                    .entityType(entityType)
                    .entityId(entityId)
                    .blockchainTxId(SyncStatus.SYNCED.name().equals(syncStatus) ? blockchainTxId : null)
                    .blockNumber(SyncStatus.SYNCED.name().equals(syncStatus) ? blockNumber : null)
                    .syncStatus(syncStatus)
                    .errorMessage(errorMessage)
                    .retryCount(SyncStatus.FAILED.name().equals(syncStatus) ? 1 : 0)
                    .lastSyncedAt(LocalDateTime.now())
                    .build();
        }

        return syncMetadataRepository.save(metadata);
    }

    /**
     * Helper: Convert SyncMetadata to DTO
     */
    private SyncStatusDto convertSyncMetadataToDto(SyncMetadata metadata) {
        return SyncStatusDto.builder()
                .entityType(metadata.getEntityType())
                .entityId(metadata.getEntityId())
                .syncStatus(metadata.getSyncStatus())
                .lastSyncedAt(metadata.getLastSyncedAt())
                .blockchainTxId(metadata.getBlockchainTxId())
                .blockNumber(metadata.getBlockNumber())
                .errorMessage(metadata.getErrorMessage())
                .retryCount(metadata.getRetryCount())
                .build();
    }
}
