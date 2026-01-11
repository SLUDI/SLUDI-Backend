package org.example.repository;

import org.example.entity.DeepfakeDetectionLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface DeepfakeDetectionLogRepository extends JpaRepository<DeepfakeDetectionLog, UUID> {

    // Find all logs ordered by detection time (newest first)
    List<DeepfakeDetectionLog> findAllByOrderByDetectedAtDesc();

    // Find logs by citizen ID
    List<DeepfakeDetectionLog> findByCitizenIdOrderByDetectedAtDesc(Long citizenId);

    // Find logs where deepfake was detected
    List<DeepfakeDetectionLog> findByDeepfakeDetectedTrueOrderByDetectedAtDesc();

    // Find logs by auth result
    List<DeepfakeDetectionLog> findByAuthResultOrderByDetectedAtDesc(String authResult);

    // Find logs within date range
    List<DeepfakeDetectionLog> findByDetectedAtBetweenOrderByDetectedAtDesc(
            LocalDateTime startDate, LocalDateTime endDate);

    // Paginated queries
    Page<DeepfakeDetectionLog> findAllByOrderByDetectedAtDesc(Pageable pageable);

    Page<DeepfakeDetectionLog> findByDeepfakeDetectedTrueOrderByDetectedAtDesc(Pageable pageable);

    // Statistics queries
    @Query("SELECT COUNT(d) FROM DeepfakeDetectionLog d WHERE d.deepfakeDetected = true")
    Long countDeepfakesDetected();

    @Query("SELECT COUNT(d) FROM DeepfakeDetectionLog d WHERE d.authResult = 'SUCCESS'")
    Long countSuccessfulAuthentications();

    @Query("SELECT COUNT(d) FROM DeepfakeDetectionLog d WHERE d.authResult LIKE 'FAILED%'")
    Long countFailedAuthentications();

    @Query("SELECT COUNT(d) FROM DeepfakeDetectionLog d")
    Long countTotalAttempts();

    // Find recent logs (last 24 hours)
    @Query("SELECT d FROM DeepfakeDetectionLog d WHERE d.detectedAt >= :since ORDER BY d.detectedAt DESC")
    List<DeepfakeDetectionLog> findRecentLogs(LocalDateTime since);
}
