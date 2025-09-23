package org.example.controller;

import jakarta.validation.Valid;
import org.example.dto.*;
import org.example.exception.HttpStatusHandler;
import org.example.exception.SludiException;
import org.example.service.WalletService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.validation.annotation.Validated;

import java.util.Map;

@RestController
@RequestMapping("/api/wallet")
@Validated
public class WalletController {

    @Autowired
    private WalletService walletService;

    /**
     * Verify DID and initiate wallet creation
     */
    @PostMapping("/verify-did")
    public ResponseEntity<ApiResponseDto<String>> verifyDid(
            @Valid @RequestBody DidVerificationRequest request) {
        try {
            String did = "did:sludi:" + request.getDid();
            String result = walletService.initiateWalletCreation(did);
            return ResponseEntity.ok(ApiResponseDto.<String>builder()
                    .success(true)
                    .message("Did verification successfully")
                    .data(result)
                    .timestamp(java.time.Instant.now())
                    .build());
        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<String>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<String>builder()
                            .success(false)
                            .message("Failed to create Wallet")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(java.time.Instant.now())
                            .build());
        }
    }

    /**
     * Verify OTP
     */
    @PostMapping("/verify-otp")
    public ResponseEntity<String> verifyOTP(
            @Valid @RequestBody OtpVerificationRequest request) {
        boolean isVerified = walletService.verifyOTP(request.getDid(), request.getOtp());
        if (isVerified) {
            return ResponseEntity.ok("OTP verified successfully. You can now create a wallet.");
        } else {
            return ResponseEntity.status(400).body("Invalid or expired OTP.");
        }
    }

    /**
     * Create wallet with password
     */
    @PostMapping("/create")
    public ResponseEntity<ApiResponseDto<Map<String, String>>> createWallet(
            @Valid @RequestBody WalletRequest request) {
        try {
            Map<String, String> result = walletService.createWallet(request.getDid(), request.getPassword());
            return ResponseEntity.ok(ApiResponseDto.<Map<String, String>>builder()
                    .success(true)
                    .message("Wallet created successfully")
                    .data(result)
                    .timestamp(java.time.Instant.now())
                    .build());
        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<Map<String, String>>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<Map<String, String>>builder()
                            .success(false)
                            .message("Failed to create Wallet")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(java.time.Instant.now())
                            .build());
        }
    }

    /**
     * Get wallet status
     */
    @GetMapping("/get/status")
    public ResponseEntity<ApiResponseDto<WalletDto>> getWalletStatus(
            @RequestParam String did,
            @RequestParam String password) {
        try {
            WalletDto walletDto = walletService.retrieveWallet(did, password);
            return ResponseEntity.ok(ApiResponseDto.<WalletDto>builder()
                    .success(true)
                    .message("Wallet retrieved successfully")
                    .data(walletDto)
                    .timestamp(java.time.Instant.now())
                    .build());
        } catch (SludiException e) {
            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<WalletDto>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(java.time.Instant.now())
                            .build());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<WalletDto>builder()
                            .success(false)
                            .message("Failed to retrieve Wallet")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(java.time.Instant.now())
                            .build());
        }
    }
}