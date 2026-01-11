package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.FaceVerificationResultDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

@Slf4j
@Service
public class DeepfakeDetectionService {

    @Autowired
    private ObjectMapper objectMapper;

    private static final String PHOTO_SPACE_API_URL = "https://deepfake.sludi.dpdns.org/predict";
    private static final String VIDEO_SPACE_API_URL = "https://Tishan-001-video-deepfake-detection.hf.space/detailed-analysis";
    private static final String QUICK_CHECK_API_URL = "https://Tishan-001-video-deepfake-detection.hf.space/quick-check";
    private static final String FACE_VERIFICATION_API_URL = "https://deepfake.sludi.dpdns.org/verify-with-embedding";
    private static final Double FACE_AUTHENTICATION_THRESHOLD = 0.80;
    private static final String UPLOAD_DIR = "uploads/videos/";

    public Map<String, Object> detectDeepfake(MultipartFile file) throws IOException {
        RestTemplate restTemplate = new RestTemplate();

        // Prepare multipart request
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", new MultipartInputStreamFileResource(file.getInputStream(), file.getOriginalFilename()));

        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);

        // Send request to Hugging Face Space
        ResponseEntity<Map> response = restTemplate.postForEntity(PHOTO_SPACE_API_URL, requestEntity, Map.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            log.error("Deepfake detection failed with status: {}", response.getStatusCode());
            throw new RuntimeException("Deepfake detection API failed: " + response.getStatusCode());
        }

        Map<String, Object> responseBody = response.getBody();
        if (responseBody == null) {
            throw new RuntimeException("Empty response from deepfake API");
        }

        log.info("Deepfake detection successful for file: {}", file.getOriginalFilename());

        // Extract response data
        String label = (String) responseBody.get("label");
        Double confidence = ((Number) responseBody.get("confidence")).doubleValue();
        Double probabilityFake = ((Number) responseBody.get("probability_fake")).doubleValue();
        Double probabilityReal = ((Number) responseBody.get("probability_real")).doubleValue();
        Integer framesAnalyzed = ((Number) responseBody.get("frames_analyzed")).intValue();
        Double processingTimeMs = ((Number) responseBody.get("processing_time_ms")).doubleValue();

        // Frame probabilities (avg, max, min)
        Map<String, Object> frameProbabilities = (Map<String, Object>) responseBody.get("frame_probabilities");

        // Build response map
        Map<String, Object> result = new HashMap<>();
        result.put("label", label);
        result.put("confidence", confidence);
        result.put("probability_fake", probabilityFake);
        result.put("probability_real", probabilityReal);
        result.put("frames_analyzed", framesAnalyzed);
        result.put("processing_time_ms", processingTimeMs);
        result.put("frame_probabilities", frameProbabilities);

        // Images are only included when deepfake is detected (label == "Fake")
        Map<String, String> images = (Map<String, String>) responseBody.get("images");
        if (images != null) {
            result.put("original", images.get("original"));
            result.put("gradcam_heatmap", images.get("gradcam_heatmap"));
            result.put("overlay", images.get("overlay"));
            result.put("gradcam_frame_index", responseBody.get("gradcam_frame_index"));
            result.put("gradcam_frame_probability", responseBody.get("gradcam_frame_probability"));
        }

        return result;
    }

    public Map<String, Object> detectVideDeepfake(MultipartFile file) throws IOException {
        RestTemplate restTemplate = new RestTemplate();

        // Prepare multipart request
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", new MultipartInputStreamFileResource(file.getInputStream(), file.getOriginalFilename()));

        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);

        try {
            // Send request to Python API
            ResponseEntity<Map> response = restTemplate.postForEntity(VIDEO_SPACE_API_URL, requestEntity, Map.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                log.error("Deepfake detection failed with status: {}", response.getStatusCode());
                throw new RuntimeException("Deepfake detection API failed: " + response.getStatusCode());
            }

            Map<String, Object> responseBody = response.getBody();
            if (responseBody == null) {
                throw new RuntimeException("Empty response from deepfake API");
            }

            log.info("Deepfake detection successful for file: {}", file.getOriginalFilename());

            // Extract response data based on the new video model format
            String label = (String) responseBody.get("label");
            Double confidence = (Double) responseBody.get("confidence");
            Double probability = (Double) responseBody.get("probability");
            Integer framesProcessed = (Integer) responseBody.get("frames_processed");

            // Extract Grad-CAM analysis data
            List<Map<String, Object>> gradcamAnalysis = (List<Map<String, Object>>) responseBody
                    .get("gradcam_analysis");
            List<Map<String, Object>> gradcamResults = new ArrayList<>();

            if (gradcamAnalysis != null) {
                for (Map<String, Object> gradcamFrame : gradcamAnalysis) {
                    Integer frameIndex = (Integer) gradcamFrame.get("frame_index");
                    Map<String, Object> images = (Map<String, Object>) gradcamFrame.get("images");

                    Map<String, Object> gradcamResult = new HashMap<>();
                    gradcamResult.put("frameIndex", frameIndex);
                    gradcamResult.put("original", images.get("original"));
                    gradcamResult.put("gradcamHeatmap", images.get("gradcam_heatmap"));
                    gradcamResult.put("overlay", images.get("overlay"));

                    gradcamResults.add(gradcamResult);
                }
            }

            // Extract visualization data
            Map<String, Object> visualization = (Map<String, Object>) responseBody.get("visualization");
            String frameMontage = (String) visualization.get("frame_montage");

            // Extract model info
            Map<String, Object> modelInfo = (Map<String, Object>) responseBody.get("model_info");
            Integer sequenceLength = (Integer) modelInfo.get("sequence_length");
            Integer inputSize = (Integer) modelInfo.get("input_size");

            // Build response map
            Map<String, Object> result = new HashMap<>();
            result.put("label", label);
            result.put("confidence", confidence);
            result.put("probability", probability);
            result.put("framesProcessed", framesProcessed);
            result.put("frameMontage", frameMontage);
            result.put("gradcamAnalysis", gradcamResults); // New field
            result.put("sequenceLength", sequenceLength);
            result.put("inputSize", inputSize);
            result.put("filename", file.getOriginalFilename());

            return result;

        } catch (Exception e) {
            log.error("Error during deepfake detection for file: {}", file.getOriginalFilename(), e);
            throw new RuntimeException("Deepfake detection failed: " + e.getMessage(), e);
        }
    }

    public Map<String, Object> quickCheckDeepfake(MultipartFile file) throws IOException {
        RestTemplate restTemplate = new RestTemplate();

        // Prepare multipart request
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", new MultipartInputStreamFileResource(file.getInputStream(), file.getOriginalFilename()));

        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);

        // Send request to Quick Check endpoint
        ResponseEntity<Map> response = restTemplate.postForEntity(QUICK_CHECK_API_URL, requestEntity, Map.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            log.error("Quick deepfake check failed with status: {}", response.getStatusCode());
            throw new RuntimeException("Quick deepfake check API failed: " + response.getStatusCode());
        }

        Map<String, Object> responseBody = response.getBody();
        if (responseBody == null) {
            throw new RuntimeException("Empty response from quick check API");
        }

        log.info("Quick deepfake check successful for file: {}", file.getOriginalFilename());

        // Extract and build simplified response
        Map<String, Object> result = new HashMap<>();
        result.put("status", responseBody.get("status"));
        result.put("prediction", responseBody.get("prediction"));
        result.put("is_fake", responseBody.get("is_fake"));
        result.put("confidence", responseBody.get("confidence"));
        result.put("processing_time", responseBody.get("processing_time"));

        return result;
    }

    public FaceVerificationResultDto faceAuthentication(
            MultipartFile videoFile,
            String embeddingBase64) throws Exception {

        RestTemplate restTemplate = new RestTemplate();

        if (videoFile == null || videoFile.isEmpty()) {
            throw new IllegalArgumentException("Video file is empty");
        }

        if (embeddingBase64 == null || embeddingBase64.trim().isEmpty()) {
            throw new IllegalArgumentException("Embedding Base64 string is empty");
        }

        try {
            // Create API request
            MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();

            ByteArrayResource fileResource = new ByteArrayResource(videoFile.getBytes()) {
                @Override
                public String getFilename() {
                    return videoFile.getOriginalFilename();
                }
            };

            body.add("file", fileResource);
            body.add("stored_embedding", embeddingBase64);
            body.add("threshold", String.valueOf(FACE_AUTHENTICATION_THRESHOLD));

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);

            HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);

            // Call FastAPI
            ResponseEntity<Map> response = restTemplate.postForEntity(
                    FACE_VERIFICATION_API_URL,
                    requestEntity,
                    Map.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new Exception("FastAPI returned error: " + response.getStatusCode());
            }

            Map<String, Object> responseBody = response.getBody();
            if (responseBody == null) {
                throw new Exception("FastAPI returned empty response");
            }

            return convertToVerificationResult(responseBody);
        } catch (Exception e) {
            log.error("Verification failed: {}", e.getMessage(), e);
            throw new Exception("Face verification failed: " + e.getMessage(), e);
        }
    }

    private FaceVerificationResultDto convertToVerificationResult(Map<String, Object> responseBody) {
        boolean success = Boolean.TRUE.equals(responseBody.get("success"));

        // Deepfake Check
        Map<String, Object> deepfakeCheck = (Map<String, Object>) responseBody.get("deepfake_check");
        boolean isAuthentic = deepfakeCheck != null && Boolean.TRUE.equals(deepfakeCheck.get("is_authentic"));
        double probabilityFake = deepfakeCheck != null
                ? ((Number) deepfakeCheck.getOrDefault("probability_fake", 0.0)).doubleValue()
                : 0.0;

        boolean isDeepfake = !isAuthentic;

        // Extract visualization data from deepfake check
        String heatmapBase64 = null;
        String overlayBase64 = null;
        String originalImageBase64 = null;

        if (deepfakeCheck != null) {
            Map<String, Object> visualizations = (Map<String, Object>) deepfakeCheck.get("visualizations");
            if (visualizations != null) {
                heatmapBase64 = (String) visualizations.get("gradcam_heatmap");
                overlayBase64 = (String) visualizations.get("overlay");
            }
            // Get original from images if present
            Map<String, Object> images = (Map<String, Object>) deepfakeCheck.get("images");
            if (images != null) {
                originalImageBase64 = (String) images.get("original");
                if (heatmapBase64 == null) {
                    heatmapBase64 = (String) images.get("gradcam_heatmap");
                }
                if (overlayBase64 == null) {
                    overlayBase64 = (String) images.get("overlay");
                }
            }
        }

        // Face Verification
        Map<String, Object> faceVerification = (Map<String, Object>) responseBody.get("face_verification");
        boolean isMatch = faceVerification != null && Boolean.TRUE.equals(faceVerification.get("is_match"));
        double similarity = faceVerification != null
                ? ((Number) faceVerification.getOrDefault("similarity", 0.0)).doubleValue()
                : 0.0;
        double thresholdUsed = faceVerification != null
                ? ((Number) faceVerification.getOrDefault("threshold_used", 0.6)).doubleValue()
                : 0.6;

        // Liveness
        Map<String, Object> livenessCheck = (Map<String, Object>) responseBody.get("liveness_check");
        boolean livenessPassed = livenessCheck != null && Boolean.TRUE.equals(livenessCheck.get("passed"));
        int blinks = livenessCheck != null ? ((Number) livenessCheck.getOrDefault("blinks_detected", 0)).intValue() : 0;

        // Processing Time
        double processingTime = ((Number) responseBody.getOrDefault("processing_time_ms", 0.0)).doubleValue();

        // Breakdown
        Map<String, Object> perf = (Map<String, Object>) responseBody.get("performance_breakdown");
        double videoProcessing = perf != null ? ((Number) perf.getOrDefault("video_processing_ms", 0.0)).doubleValue()
                : 0.0;
        double deepfakeTime = perf != null ? ((Number) perf.getOrDefault("deepfake_detection_ms", 0.0)).doubleValue()
                : 0.0;
        double faceVerificationTime = perf != null
                ? ((Number) perf.getOrDefault("face_verification_ms", 0.0)).doubleValue()
                : 0.0;

        return FaceVerificationResultDto.builder()
                .success(success)
                .isMatch(isMatch)
                .similarity(similarity)
                .deepfakeDetected(isDeepfake)
                .confidence(probabilityFake)
                .probabilityFake(probabilityFake)
                .livenessCheckPassed(livenessPassed)
                .blinksDetected(blinks)
                .processingTimeMs(processingTime)
                .thresholdUsed(thresholdUsed)
                .heatmapBase64(heatmapBase64)
                .overlayBase64(overlayBase64)
                .originalImageBase64(originalImageBase64)
                .build();
    }

    // Helper for Multipart upload
    private static class MultipartInputStreamFileResource extends InputStreamResource {
        private final String filename;

        public MultipartInputStreamFileResource(InputStream inputStream, String filename) {
            super(inputStream);
            this.filename = filename;
        }

        @Override
        public String getFilename() {
            return this.filename;
        }

        @Override
        public long contentLength() throws IOException {
            return -1;
        }
    }
}