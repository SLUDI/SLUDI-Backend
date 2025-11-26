package org.example.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class HuggingFaceResponse {
    private boolean success;
    private String result;
    private String message;

    @JsonProperty("deepfake_check")
    private DeepfakeCheck deepfakeCheck;

    @JsonProperty("liveness_check")
    private LivenessCheck livenessCheck;

    @JsonProperty("face_verification")
    private FaceVerification faceVerification;

    @JsonProperty("processing_time_ms")
    private Double processingTimeMs;

    @JsonProperty("performance_breakdown")
    private PerformanceBreakdown performanceBreakdown;

    @JsonProperty("model_info")
    private ModelInfo modelInfo;

    // Nested DTOs
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class DeepfakeCheck {
        @JsonProperty("is_authentic")
        private boolean isAuthentic;

        @JsonProperty("probability_fake")
        private double probabilityFake;

        @JsonProperty("probability_real")
        private double probabilityReal;

        private double confidence;

        @JsonProperty("num_faces_analyzed")
        private int numFacesAnalyzed;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class LivenessCheck {
        private boolean passed;

        @JsonProperty("blinks_detected")
        private int blinksDetected;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class FaceVerification {
        @JsonProperty("is_match")
        private boolean isMatch;

        private double similarity;

        @JsonProperty("threshold_used")
        private double thresholdUsed;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PerformanceBreakdown {
        @JsonProperty("video_processing_ms")
        private double videoProcessingMs;

        @JsonProperty("deepfake_detection_ms")
        private double deepfakeDetectionMs;

        @JsonProperty("face_verification_ms")
        private double faceVerificationMs;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ModelInfo {
        @JsonProperty("deepfake_model")
        private String deepfakeModel;

        @JsonProperty("verification_model")
        private String verificationModel;

        @JsonProperty("file_processed")
        private String fileProcessed;

        @JsonProperty("faces_analyzed")
        private int facesAnalyzed;
    }
}
