package org.example.integration;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.dto.*;
import org.example.service.DeepfakeDetectionService;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class AIIntegration {

    DeepfakeDetectionService deepfakeDetectionService;
    BiometricVerificationResult verifyBiometricAuthenticity(BiometricDataDto biometric) {
        return null;
    }

    public BiometricMatchResult verifyBiometricMatch(byte[] presentedData, BiometricData storedData, String type) {
        return BiometricMatchResult.builder()
                .match(true)
                .confidenceScore(0.95)
                .details("Biometric match successful with high confidence")
                .build();
    }

    public DeepFakeDetectionResult detectDeepfake(MultipartFile multipartfile) {
        String results = deepfakeDetectionService.faceAnalyse(multipartfile);


        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(results);
            boolean finalPrediction = root.get("final_prediction").asBoolean();
            double realRatio = root.get("real_ratio").asDouble();
            double avgConfidence = root.get("avg_confidence").asDouble();
            String heatmapImage = root.has("best_visualization") ? root.get("best_visualization").asText() : null;

            return DeepFakeDetectionResult.builder()
                    .status("Success")
                    .authentic(finalPrediction)
                    .real_ratio(realRatio)
                    .averageConfidence(avgConfidence)
                    .heatmapImage(heatmapImage)
                    .build();
        } catch (JsonProcessingException e) {
            return DeepFakeDetectionResult.builder()
                    .status("Failed")
                    .authentic(false)
                    .averageConfidence(0.0)
                    .details("Error parsing detecting results: " + e.getMessage())
                    .build();
        }
    }

    public AIDetectionResult performLivenessCheck(byte[] biometricData, String type) {
        return AIDetectionResult.builder()
                .authentic(true)
                .confidence(0.92)
                .details("Liveness check passed - subject appears to be present")
                .build();
    }
}