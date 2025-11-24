package org.example.service;

import lombok.extern.slf4j.Slf4j;
import org.example.dto.FaceVerificationResultDto;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.DataOutput;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class DeepfakeDetectionService {

    private static final String PHOTO_SPACE_API_URL = "https://Tishan-001-deepfake-detector.hf.space/predict";
    private static final String VIDEO_SPACE_API_URL = "https://Tishan-001-video-deepfake-detection.hf.space/detailed-analysis";
    private static final String QUICK_CHECK_API_URL = "https://Tishan-001-video-deepfake-detection.hf.space/quick-check";
    private static final String FACE_DETECTION_API_URL = "https://Ishan1998-Feature.hf.space/verify-with-embedding";
    private static final Double FACE_AUTHENTICATION_THRESHOLD = 0.90;

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
        Double confidence = (Double) responseBody.get("confidence");

        Map<String, String> images = (Map<String, String>) responseBody.get("images");

        // Build response map
        Map<String, Object> result = new HashMap<>();
        result.put("label", label);
        result.put("confidence", confidence);
        result.put("original", images.get("original"));
        result.put("gradcam_heatmap", images.get("gradcam_heatmap"));
        result.put("overlay", images.get("overlay"));

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
            List<Map<String, Object>> gradcamAnalysis = (List<Map<String, Object>>) responseBody.get("gradcam_analysis");
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
            String storedEmbedding) throws Exception {
        RestTemplate restTemplate = new RestTemplate();

        try {
            // Create headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);

            // Create multipart body
            MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();

            // Add video file
            ByteArrayResource fileResource = new ByteArrayResource(videoFile.getBytes()) {
                @Override
                public String getFilename() {
                    return videoFile.getOriginalFilename();
                }
            };
            body.add("file", fileResource);

            // Add stored embedding
            body.add("stored_embedding", storedEmbedding);

            // Add threshold
            body.add("threshold", String.valueOf(FACE_AUTHENTICATION_THRESHOLD));

            // Create HTTP entity
            HttpEntity<MultiValueMap<String, Object>> requestEntity =
                    new HttpEntity<>(body, headers);

            // Make the request
            ResponseEntity<HuggingFaceResponse> response = restTemplate.postForEntity(
                    FACE_DETECTION_API_URL,
                    requestEntity,
                    HuggingFaceResponse.class
            );

            // Parse response
            HuggingFaceResponse hfResponse = response.getBody();
            if (hfResponse == null) {
                throw new Exception("Empty response from HuggingFace API");
            }

            return convertToVerificationResult(hfResponse);

        } catch (Exception e) {
            log.error("Error during HuggingFace verification: {}", e.getMessage(), e);
            throw new Exception("Error during HuggingFace verification: " + e.getMessage(), e);

        }
    }
    private FaceVerificationResultDto convertToVerificationResult(HuggingFaceResponse response) {
        boolean isMatch = response.isMatch();
        double similarity = response.getSimilarity();

        String message = isMatch ?
                "Identity verified successfully" :
                "Identity verification failed";

        // Check for deepfake detection
        if (response.isDeepfake()) {
            message = "Deepfake detected - verification failed";
            isMatch = false;
        }

        return FaceVerificationResultDto.builder()
                .isMatch(isMatch)
                .similarity(similarity)
                .message(message)
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
    class HuggingFaceResponse {
        private boolean is_match;
        private double similarity;
        private boolean deepfake;

        // Constructors
        public HuggingFaceResponse() {}

        // Getters and Setters
        public boolean isMatch() { return is_match; }
        public void setIs_match(boolean is_match) { this.is_match = is_match; }

        public double getSimilarity() { return similarity; }
        public void setSimilarity(double similarity) { this.similarity = similarity; }

        public boolean isDeepfake() { return deepfake; }
        public void setDeepfake(boolean deepfake) { this.deepfake = deepfake; }
    }
}