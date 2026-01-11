package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "deepfake_detection_logs")
public class DeepfakeDetectionLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "citizen_id")
    private UUID citizenId;

    @Column(name = "citizen_did")
    private String citizenDid;

    @Column(name = "citizen_name")
    private String citizenName;

    @Column(name = "deepfake_detected")
    private Boolean deepfakeDetected;

    @Column(name = "confidence")
    private Double confidence;

    @Column(name = "probability_fake")
    private Double probabilityFake;

    @Column(name = "similarity_score")
    private Double similarityScore;

    @Column(name = "liveness_check_passed")
    private Boolean livenessCheckPassed;

    @Column(name = "blinks_detected")
    private Integer blinksDetected;

    @Column(name = "heatmap_base64", columnDefinition = "TEXT")
    private String heatmapBase64;

    @Column(name = "overlay_base64", columnDefinition = "TEXT")
    private String overlayBase64;

    @Column(name = "original_image_base64", columnDefinition = "TEXT")
    private String originalImageBase64;

    @Column(name = "auth_result")
    private String authResult; // SUCCESS, FAILED_DEEPFAKE, FAILED_MATCH, FAILED_LIVENESS

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    private String userAgent;

    @Column(name = "processing_time_ms")
    private Double processingTimeMs;

    @Column(name = "detected_at")
    private LocalDateTime detectedAt;

    @Column(name = "threshold_used")
    private Double thresholdUsed;
}
