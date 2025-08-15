package org.example.controller;

import org.example.dto.SystemStatsDto;
import org.example.integration.HyperledgerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/blockchain")
@CrossOrigin(origins = "*")
public class BlockchainController {

    @Autowired
    private HyperledgerService hyperledgerService;

    @PostMapping("/init-ledger")
    public ResponseEntity<String> initializeLedger() {
        try {
            hyperledgerService.initializeLedger();
            return ResponseEntity.ok("Ledger initialized successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Failed to initialize ledger: " + e.getMessage());
        }
    }

    @GetMapping("/system-stats")
    public ResponseEntity<?> getSystemStats() {
        try {
            SystemStatsDto stats = hyperledgerService.getSystemStats();
            return ResponseEntity.ok(stats);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("An unexpected error occurred while fetching system statistics.");
        }
    }
}