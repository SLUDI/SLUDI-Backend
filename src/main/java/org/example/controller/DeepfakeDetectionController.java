package org.example.controller;

import lombok.RequiredArgsConstructor;
import org.example.dto.ApiResponseDto;
import org.example.service.DeepfakeDetectionService;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.Instant;
import java.util.Map;

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
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<Map<String, Object>>builder()
                            .success(false)
                            .message("Deepfake detection failed: " + e.getMessage())
                            .timestamp(Instant.now())
                            .build());
        }
    }
}
