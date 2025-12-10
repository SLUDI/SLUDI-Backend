package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.ApiResponseDto;
import org.example.dto.SyncReportDto;
import org.example.dto.SyncStatusDto;
import org.example.service.BlockchainSyncService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/sync")
@Tag(name = "Blockchain Synchronization", description = "APIs for synchronizing blockchain data to PostgreSQL")
public class BlockchainSyncController {

    private final BlockchainSyncService blockchainSyncService;

    public BlockchainSyncController(BlockchainSyncService blockchainSyncService) {
        this.blockchainSyncService = blockchainSyncService;
    }

    /**
     * Sync a single DID from blockchain to database
     */
    @Operation(summary = "Sync Single DID", description = "Synchronize a specific DID from blockchain to PostgreSQL database")
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping("/did/{didId}")
    public ResponseEntity<ApiResponseDto<SyncStatusDto>> syncDID(@PathVariable String didId) {
        log.info("Received request to sync DID: {}", didId);

        SyncStatusDto status = blockchainSyncService.syncDIDFromBlockchain(didId);

        return ResponseEntity.ok(ApiResponseDto.<SyncStatusDto>builder()
                .success(true)
                .message("DID synchronization completed")
                .data(status)
                .build());
    }

    /**
     * Sync a single Verifiable Credential from blockchain to database
     */
    @Operation(summary = "Sync Single Credential", description = "Synchronize a specific Verifiable Credential from blockchain to PostgreSQL database")
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping("/credential/{credentialId}")
    public ResponseEntity<ApiResponseDto<SyncStatusDto>> syncCredential(@PathVariable String credentialId) {
        log.info("Received request to sync Credential: {}", credentialId);

        SyncStatusDto status = blockchainSyncService.syncCredentialFromBlockchain(credentialId);

        return ResponseEntity.ok(ApiResponseDto.<SyncStatusDto>builder()
                .success(true)
                .message("Credential synchronization completed")
                .data(status)
                .build());
    }

    /**
     * Sync all DIDs from blockchain to database
     */
    @Operation(summary = "Sync All DIDs", description = "Synchronize all DIDs from blockchain to PostgreSQL database")
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping("/did/all")
    public ResponseEntity<ApiResponseDto<SyncReportDto>> syncAllDIDs() {
        log.info("Received request to sync all DIDs");

        SyncReportDto report = blockchainSyncService.syncAllDIDs();

        return ResponseEntity.ok(ApiResponseDto.<SyncReportDto>builder()
                .success(true)
                .message("All DIDs synchronization completed")
                .data(report)
                .build());
    }

    /**
     * Sync all Verifiable Credentials from blockchain to database
     */
    @Operation(summary = "Sync All Credentials", description = "Synchronize all Verifiable Credentials from blockchain to PostgreSQL database")
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping("/credential/all")
    public ResponseEntity<ApiResponseDto<SyncReportDto>> syncAllCredentials() {
        log.info("Received request to sync all Credentials");

        SyncReportDto report = blockchainSyncService.syncAllCredentials();

        return ResponseEntity.ok(ApiResponseDto.<SyncReportDto>builder()
                .success(true)
                .message("All Credentials synchronization completed")
                .data(report)
                .build());
    }

    /**
     * Retry failed synchronizations
     */
    @Operation(summary = "Retry Failed Syncs", description = "Retry all failed synchronizations that haven't exceeded max retry count")
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping("/retry-failed")
    public ResponseEntity<ApiResponseDto<SyncReportDto>> retryFailedSyncs() {
        log.info("Received request to retry failed synchronizations");

        SyncReportDto report = blockchainSyncService.retryFailedSyncs();

        return ResponseEntity.ok(ApiResponseDto.<SyncReportDto>builder()
                .success(true)
                .message("Failed synchronizations retry completed")
                .data(report)
                .build());
    }

    /**
     * Get sync status for a specific entity
     */
    @Operation(summary = "Get Sync Status", description = "Get synchronization status for a specific DID or Credential")
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/status")
    public ResponseEntity<ApiResponseDto<SyncStatusDto>> getSyncStatus(
            @RequestParam String entityType,
            @RequestParam String entityId) {
        log.info("Received request to get sync status for {} {}", entityType, entityId);

        SyncStatusDto status = blockchainSyncService.getSyncStatus(entityType, entityId);

        return ResponseEntity.ok(ApiResponseDto.<SyncStatusDto>builder()
                .success(true)
                .message("Sync status retrieved successfully")
                .data(status)
                .build());
    }

    /**
     * Get all sync statuses
     */
    @Operation(summary = "Get All Sync Statuses", description = "Get synchronization status for all entities")
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/status/all")
    public ResponseEntity<ApiResponseDto<List<SyncStatusDto>>> getAllSyncStatuses() {
        log.info("Received request to get all sync statuses");

        List<SyncStatusDto> statuses = blockchainSyncService.getAllSyncStatuses();

        return ResponseEntity.ok(ApiResponseDto.<List<SyncStatusDto>>builder()
                .success(true)
                .message("All sync statuses retrieved successfully")
                .data(statuses)
                .build());
    }

    /**
     * Trigger full synchronization (DIDs + Credentials)
     */
    @Operation(summary = "Full Synchronization", description = "Trigger complete synchronization of all DIDs and Credentials")
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping("/full")
    public ResponseEntity<ApiResponseDto<String>> fullSync() {
        log.info("Received request for full synchronization");

        // Run async
        new Thread(() -> {
            try {
                blockchainSyncService.syncAllDIDs();
                blockchainSyncService.syncAllCredentials();
                log.info("Full synchronization completed successfully");
            } catch (Exception e) {
                log.error("Full synchronization failed: {}", e.getMessage(), e);
            }
        }).start();

        return ResponseEntity.accepted().body(ApiResponseDto.<String>builder()
                .success(true)
                .message("Full synchronization started in background")
                .data("Check sync status endpoints for progress")
                .build());
    }
}
