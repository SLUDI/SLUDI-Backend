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
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@RestController
@RequestMapping("/api/deepfake")
@RequiredArgsConstructor
public class DeepfakeDetectionController {

    private final DeepfakeDetectionService deepfakeDetectionService;

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
