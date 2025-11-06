package org.example.controller;

import lombok.RequiredArgsConstructor;
import org.example.dto.ApiResponseDto;
import org.example.service.DeepfakeDetectionService;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@RestController
@RequestMapping("/api/deepfake")
public class DeepfakeDetectionController {

    private final DeepfakeDetectionService deepfakeDetectionService;

    public DeepfakeDetectionController(DeepfakeDetectionService deepfakeDetectionService) {
        this.deepfakeDetectionService = deepfakeDetectionService;
    }

    @PostMapping(value = "/detect", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ApiResponseDto<Map<String, Object>>> detect(@RequestParam("file") MultipartFile file) {
        try {
            Map<String, Object> result = deepfakeDetectionService.detectDeepfake(file);

            return ResponseEntity.ok(
                    ApiResponseDto.<Map<String, Object>>builder()
                            .success(true)
                            .message("Deepfake detection successful")
                            .data(result)
                            .timestamp(Instant.now())
                            .build()
            );

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<Map<String, Object>>builder()
                            .success(false)
                            .message("Deepfake detection failed: " + e.getMessage())
                            .timestamp(Instant.now())
                            .build());
        }
    }

    @PostMapping(value = "/detect/get-image", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> detectGetImage(@RequestParam("file") MultipartFile file) {
        try {
            Map<String, Object> result = deepfakeDetectionService.detectDeepfake(file);

            // extract images (Base64)
            Map<String, String> images = Map.of(
                    "original.png", (String) result.get("original"),
                    "gradcam_heatmap.png", (String) result.get("gradcam_heatmap"),
                    "overlay.png", (String) result.get("overlay")
            );

            // convert to zip
            byte[] zipBytes = createZipFromBase64(images);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.setContentDisposition(ContentDisposition.attachment().filename("deepfake_results.zip").build());

            return new ResponseEntity<>(new ByteArrayResource(zipBytes), headers, HttpStatus.OK);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "message", "Deepfake detection failed: " + e.getMessage(),
                            "timestamp", Instant.now()
                    ));
        }
    }

    @PostMapping(value = "/detect/quick-check", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> detectQuickCheck(@RequestParam("file") MultipartFile file) {
        try {
            Map<String, Object> result = deepfakeDetectionService.quickCheckDeepfake(file);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of(
                            "success", true,
                            "data", Map.of(
                                    "prediction", result.get("prediction"),
                                    "is_fake", result.get("is_fake"),
                                    "confidence", result.get("confidence"),
                                    "processing_time", result.get("processing_time")
                            ),
                            "message", "Quick deepfake check completed successfully",
                            "timestamp", Instant.now()
                    ));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "message", "Quick deepfake check failed: " + e.getMessage(),
                            "timestamp", Instant.now()
                    ));
        }
    }

    @PostMapping(value = "/detect/video", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> detectVideo(@RequestParam("file") MultipartFile file) {
        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(Map.of(
                                "success", false,
                                "message", "File is empty",
                                "timestamp", Instant.now()
                        ));
            }

            if (!file.getContentType().startsWith("video/")) {
                return ResponseEntity.badRequest()
                        .body(Map.of(
                                "success", false,
                                "message", "Please upload a video file",
                                "timestamp", Instant.now()
                        ));
            }

            Map<String, Object> result = deepfakeDetectionService.detectVideDeepfake(file);

            // Extract data from the response
            String label = (String) result.get("label");
            Double confidence = (Double) result.get("confidence");
            Integer framesProcessed = (Integer) result.get("framesProcessed");
            String frameMontage = (String) result.get("frameMontage");

            // Extract Grad-CAM analysis
            List<Map<String, Object>> gradcamAnalysis = (List<Map<String, Object>>) result.get("gradcamAnalysis");

            // Create images map for ZIP
            Map<String, String> images = new HashMap<>();

            // Add frame montage (grid of all processed frames)
            images.put("frame_montage.png", frameMontage);

            // Add Grad-CAM visualizations for each analyzed frame
            if (gradcamAnalysis != null && !gradcamAnalysis.isEmpty()) {
                for (Map<String, Object> gradcamFrame : gradcamAnalysis) {
                    Integer frameIndex = (Integer) gradcamFrame.get("frameIndex");
                    String original = (String) gradcamFrame.get("original");
                    String gradcamHeatmap = (String) gradcamFrame.get("gradcamHeatmap");
                    String overlay = (String) gradcamFrame.get("overlay");

                    // Create folder structure for each frame
                    String frameFolder = String.format("frame_%02d/", frameIndex + 1);

                    images.put(frameFolder + "original.png", original);
                    images.put(frameFolder + "heatmap.png", gradcamHeatmap);
                    images.put(frameFolder + "overlay.png", overlay);
                }
            }

            // Add a summary text file with prediction results
            String summary = createSummaryTextFile(label, confidence, framesProcessed, gradcamAnalysis);
            images.put("prediction_summary.txt", Base64.getEncoder().encodeToString(summary.getBytes()));

            // Convert to zip
            byte[] zipBytes = createZipFromBase64(images);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.setContentDisposition(ContentDisposition.attachment().filename("deepfake_video_results.zip").build());

            return new ResponseEntity<>(new ByteArrayResource(zipBytes), headers, HttpStatus.OK);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "message", "Deepfake detection failed: " + e.getMessage(),
                            "timestamp", Instant.now()
                    ));
        }
    }

    private String createSummaryTextFile(String label, Double confidence, Integer framesProcessed,
                                         List<Map<String, Object>> gradcamAnalysis) {
        StringBuilder summary = new StringBuilder();
        summary.append("DEEPFAKE DETECTION RESULTS\n");
        summary.append("==========================\n\n");

        summary.append("Prediction: ").append(label).append("\n");
        summary.append(String.format("Confidence: %.2f%%\n", confidence * 100));
        summary.append("Frames Processed: ").append(framesProcessed).append("\n");
        summary.append("Analysis Timestamp: ").append(Instant.now()).append("\n\n");

        summary.append("GRAD-CAM ANALYSIS FRAMES\n");
        summary.append("========================\n");

        if (gradcamAnalysis != null && !gradcamAnalysis.isEmpty()) {
            for (Map<String, Object> frame : gradcamAnalysis) {
                Integer frameIndex = (Integer) frame.get("frameIndex");
                summary.append(String.format("Frame %d: Analyzed with Grad-CAM visualization\n", frameIndex + 1));
            }
        }

        summary.append("\nFILE STRUCTURE\n");
        summary.append("==============\n");
        summary.append("- frame_montage.png: Overview of all processed frames\n");
        summary.append("- frame_XX/: Folders containing analysis for each key frame\n");
        summary.append("  - original.png: Original frame\n");
        summary.append("  - heatmap.png: Grad-CAM heatmap visualization\n");
        summary.append("  - overlay.png: Original frame with heatmap overlay\n");

        return summary.toString();
    }

    private byte[] createZipFromBase64(Map<String, String> images) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zipOut = new ZipOutputStream(baos)) {
            for (Map.Entry<String, String> entry : images.entrySet()) {
                byte[] imgBytes = Base64.getDecoder().decode(entry.getValue());
                ZipEntry zipEntry = new ZipEntry(entry.getKey());
                zipOut.putNextEntry(zipEntry);
                zipOut.write(imgBytes);
                zipOut.closeEntry();
            }
        }
        return baos.toByteArray();
    }

}
