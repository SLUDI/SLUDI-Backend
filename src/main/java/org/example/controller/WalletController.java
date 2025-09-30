package org.example.controller;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.exception.HttpStatusHandler;
import org.example.exception.SludiException;
import org.example.service.WalletService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.validation.annotation.Validated;

import java.time.Instant;
import java.util.Map;

@Slf4j
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

        String did = "did:sludi:" + request.getDid();
        log.info("Received DID verification request for DID [{}]", did);

        try {
            String result = walletService.initiateWalletCreation(did);
            log.info("DID [{}] verified successfully", did);

            return ResponseEntity.ok(ApiResponseDto.<String>builder()
                    .success(true)
                    .message("DID verification successful")
                    .data(result)
                    .timestamp(Instant.now())
                    .build());

        } catch (SludiException e) {
            log.warn("DID verification failed for [{}], errorCode [{}], message [{}]",
                    did, e.getErrorCode(), e.getMessage());

            return ResponseEntity.status(HttpStatusHandler.getStatus(e.getErrorCode()))
                    .body(ApiResponseDto.<String>builder()
                            .success(false)
                            .message(e.getMessage())
                            .errorCode(e.getErrorCode())
                            .timestamp(Instant.now())
                            .build());

        } catch (Exception e) {
            log.error("Unexpected error while verifying DID [{}]: {}", did, e.getMessage(), e);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<String>builder()
                            .success(false)
                            .message("Failed to create Wallet")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
        }
    }

    /**
     * Verify OTP for DID
     */
    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponseDto<String>> verifyOTP(
            @Valid @RequestBody OtpVerificationRequest request) {

        String did = "did:sludi:" + request.getDid();
        log.info("Received OTP verification request for DID [{}]", did);

        try {
            boolean isVerified = walletService.verifyOTP(did, request.getOtp());

            if (isVerified) {
                log.info("OTP verified successfully for DID [{}]", did);
                return ResponseEntity.ok(ApiResponseDto.<String>builder()
                        .success(true)
                        .message("OTP verified successfully.")
                        .timestamp(Instant.now())
                        .build());
            } else {
                log.warn("OTP verification failed for DID [{}] with OTP [{}]", did, request.getOtp());
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ApiResponseDto.<String>builder()
                                .success(false)
                                .message("Invalid or expired OTP.")
                                .errorCode("INVALID_OTP")
                                .timestamp(Instant.now())
                                .build());
            }

        } catch (Exception e) {
            log.error("Unexpected error while verifying OTP for DID [{}]: {}", did, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponseDto.<String>builder()
                            .success(false)
                            .message("Failed to verify OTP")
                            .errorCode("INTERNAL_ERROR")
                            .timestamp(Instant.now())
                            .build());
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