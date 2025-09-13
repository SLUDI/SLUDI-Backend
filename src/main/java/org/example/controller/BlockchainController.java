package org.example.controller;

import org.example.dto.ApiResponseDto;
import org.example.dto.SystemStatsDto;
import org.example.service.HyperledgerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/blockchain")
@CrossOrigin(origins = "*")
public class BlockchainController {

    @Autowired
    private HyperledgerService hyperledgerService;

    @PostMapping("/init-ledger")
    public ResponseEntity<ApiResponseDto<Map<String, String>>> initializeLedger() {
        try {
            hyperledgerService.initializeLedger();

            Map<String, String> data = Map.of("status", "initialized");

            return ResponseEntity.ok(
                    ApiResponseDto.<Map<String, String>>builder()
                            .success(true)
                            .message("Ledger initialized successfully")
                            .data(data)
                            .timestamp(Instant.now())
                            .build()
            );
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<Map<String, String>>builder()
                            .success(false)
                            .message("Failed to initialize ledger: " + e.getMessage())
                            .timestamp(Instant.now())
                            .build());
        }
    }

    @GetMapping("/system-stats")
    public ResponseEntity<ApiResponseDto<SystemStatsDto>> getSystemStats() {
        try {
            SystemStatsDto stats = hyperledgerService.getSystemStats();

            return ResponseEntity.ok(
                    ApiResponseDto.<SystemStatsDto>builder()
                            .success(true)
                            .message("System stats fetched successfully")
                            .data(stats)
                            .timestamp(Instant.now())
                            .build()
            );
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<SystemStatsDto>builder()
                            .success(false)
                            .message("An unexpected error occurred while fetching system statistics: " + e.getMessage())
                            .timestamp(Instant.now())
                            .build());
        }
    }
}