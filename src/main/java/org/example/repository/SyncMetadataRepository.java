package org.example.repository;

import org.example.entity.SyncMetadata;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface SyncMetadataRepository extends JpaRepository<SyncMetadata, Long> {

    Optional<SyncMetadata> findByEntityTypeAndEntityId(String entityType, String entityId);

    List<SyncMetadata> findBySyncStatus(String syncStatus);

    List<SyncMetadata> findByEntityType(String entityType);

    List<SyncMetadata> findBySyncStatusAndRetryCountLessThan(String syncStatus, Integer maxRetries);

    List<SyncMetadata> findByLastSyncedAtBefore(LocalDateTime dateTime);

    boolean existsByEntityTypeAndEntityId(String entityType, String entityId);
}
