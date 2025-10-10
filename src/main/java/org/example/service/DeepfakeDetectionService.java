package org.example.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
public class DeepfakeDetectionService {

    private static final String PYTHON_API_URL = "https://Tishan-001-deepfake-detector.hf.space/predict";

    public Map<String, Object> detectDeepfake(MultipartFile file) throws IOException {
        RestTemplate restTemplate = new RestTemplate();

        // Prepare multipart request
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", new MultipartInputStreamFileResource(file.getInputStream(), file.getOriginalFilename()));

        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);

        // Send request to Hugging Face Space
        ResponseEntity<Map> response = restTemplate.postForEntity(PYTHON_API_URL, requestEntity, Map.class);

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
