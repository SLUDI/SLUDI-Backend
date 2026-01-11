package org.example.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.ApiResponseDto;
import org.example.entity.DeepfakeDetectionLog;
import org.example.repository.DeepfakeDetectionLogRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/deepfake/logs")
@RequiredArgsConstructor
public class DeepfakeLogController {

        private final DeepfakeDetectionLogRepository deepfakeDetectionLogRepository;

        /**
         * Get all deepfake detection logs with pagination
         */
        @GetMapping
        public ResponseEntity<ApiResponseDto<Map<String, Object>>> getAllLogs(
                        @RequestParam(defaultValue = "0") int page,
                        @RequestParam(defaultValue = "20") int size,
                        @RequestParam(required = false) Boolean deepfakeOnly) {

                Pageable pageable = PageRequest.of(page, size);
                Page<DeepfakeDetectionLog> logsPage;

                if (Boolean.TRUE.equals(deepfakeOnly)) {
                        logsPage = deepfakeDetectionLogRepository
                                        .findByDeepfakeDetectedTrueOrderByDetectedAtDesc(pageable);
                } else {
                        logsPage = deepfakeDetectionLogRepository.findAllByOrderByDetectedAtDesc(pageable);
                }

                Map<String, Object> response = new HashMap<>();
                response.put("logs", logsPage.getContent());
                response.put("currentPage", logsPage.getNumber());
                response.put("totalItems", logsPage.getTotalElements());
                response.put("totalPages", logsPage.getTotalPages());

                return ResponseEntity.ok(
                                ApiResponseDto.<Map<String, Object>>builder()
                                                .success(true)
                                                .message("Deepfake detection logs retrieved successfully")
                                                .data(response)
                                                .timestamp(Instant.now())
                                                .build());
        }

        /**
         * Get a specific log by ID
         */
        @GetMapping("/{id}")
        public ResponseEntity<ApiResponseDto<DeepfakeDetectionLog>> getLogById(@PathVariable UUID id) {
                return deepfakeDetectionLogRepository.findById(id)
                                .map(logEntry -> ResponseEntity.ok(
                                                ApiResponseDto.<DeepfakeDetectionLog>builder()
                                                                .success(true)
                                                                .message("Log entry retrieved successfully")
                                                                .data(logEntry)
                                                                .timestamp(Instant.now())
                                                                .build()))
                                .orElse(ResponseEntity.notFound().build());
        }

        /**
         * Get statistics about deepfake detections
         */
        @GetMapping("/stats")
        public ResponseEntity<ApiResponseDto<Map<String, Object>>> getStats() {
                Long totalAttempts = deepfakeDetectionLogRepository.countTotalAttempts();
                Long deepfakesDetected = deepfakeDetectionLogRepository.countDeepfakesDetected();
                Long successfulAuths = deepfakeDetectionLogRepository.countSuccessfulAuthentications();
                Long failedAuths = deepfakeDetectionLogRepository.countFailedAuthentications();

                // Get recent logs (last 24 hours)
                List<DeepfakeDetectionLog> recentLogs = deepfakeDetectionLogRepository.findRecentLogs(
                                LocalDateTime.now().minusHours(24));

                Map<String, Object> stats = new HashMap<>();
                stats.put("totalAttempts", totalAttempts);
                stats.put("deepfakesDetected", deepfakesDetected);
                stats.put("successfulAuthentications", successfulAuths);
                stats.put("failedAuthentications", failedAuths);
                stats.put("recentAttemptsCount", recentLogs.size());
                stats.put("deepfakeDetectionRate", totalAttempts > 0
                                ? (double) deepfakesDetected / totalAttempts * 100
                                : 0.0);

                return ResponseEntity.ok(
                                ApiResponseDto.<Map<String, Object>>builder()
                                                .success(true)
                                                .message("Statistics retrieved successfully")
                                                .data(stats)
                                                .timestamp(Instant.now())
                                                .build());
        }

        /**
         * Get logs by citizen ID
         */
        @GetMapping("/citizen/{citizenId}")
        public ResponseEntity<ApiResponseDto<List<DeepfakeDetectionLog>>> getLogsByCitizen(
                        @PathVariable UUID citizenId) {

                List<DeepfakeDetectionLog> logs = deepfakeDetectionLogRepository
                                .findByCitizenIdOrderByDetectedAtDesc(citizenId);

                return ResponseEntity.ok(
                                ApiResponseDto.<List<DeepfakeDetectionLog>>builder()
                                                .success(true)
                                                .message("Citizen logs retrieved successfully")
                                                .data(logs)
                                                .timestamp(Instant.now())
                                                .build());
        }

        /**
         * Get logs by auth result (SUCCESS, FAILED_DEEPFAKE, FAILED_MATCH,
         * FAILED_LIVENESS)
         */
        @GetMapping("/result/{authResult}")
        public ResponseEntity<ApiResponseDto<List<DeepfakeDetectionLog>>> getLogsByResult(
                        @PathVariable String authResult) {

                List<DeepfakeDetectionLog> logs = deepfakeDetectionLogRepository
                                .findByAuthResultOrderByDetectedAtDesc(authResult);

                return ResponseEntity.ok(
                                ApiResponseDto.<List<DeepfakeDetectionLog>>builder()
                                                .success(true)
                                                .message("Logs retrieved successfully for result: " + authResult)
                                                .data(logs)
                                                .timestamp(Instant.now())
                                                .build());
        }
}
