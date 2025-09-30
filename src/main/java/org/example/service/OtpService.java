package org.example.service;

import lombok.extern.slf4j.Slf4j;
import org.example.dto.OTP;
import org.example.entity.OtpEntity;
import org.example.repository.OtpRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Slf4j
@Service
@Transactional
public class OtpService {

    private static final int OTP_LENGTH = 6;
    private static final int EXPIRY_MINUTES = 15;

    private final SecureRandom random = new SecureRandom();

    @Autowired
    private MailService mailService;

    @Autowired
    private OtpRepository otpRepository;

    /**
     * Generate a 6-digit OTP with an expiry time.
     */
    public OTP generateOTP(String did) {
        int otp = 100000 + random.nextInt(900000);
        Instant expiryTime = Instant.now().plus(EXPIRY_MINUTES, ChronoUnit.MINUTES);

        // Invalidate old OTPs
        otpRepository.findAllByDidAndUsedFalse(did).forEach(o -> {
            o.setUsed(true);
            otpRepository.save(o);
        });

        OtpEntity entity = OtpEntity.builder()
                .did(did)
                .otpCode(String.valueOf(otp))
                .expiryTime(expiryTime)
                .used(false)
                .createdAt(Instant.now())
                .build();

        otpRepository.save(entity);

        log.info("Generated OTP [{}] for DID [{}], expires at [{}]", otp, did, expiryTime);
        return new OTP(entity.getOtpCode(), expiryTime);
    }

    /**
     * Validate OTP for a DID.
     * Marks OTP as used if valid.
     */
    public boolean verifyOTP(String did, String userInput) {
        return otpRepository.findTopByDidAndUsedFalseOrderByExpiryTimeDesc(did)
                .map(otp -> {
                    log.debug("Found OTP [{}] for DID [{}], expiry [{}]", otp.getOtpCode(), did, otp.getExpiryTime());

                    if (otp.getExpiryTime().isBefore(Instant.now())) {
                        log.warn("OTP [{}] for DID [{}] has expired", otp.getOtpCode(), did);
                        return false;
                    }

                    if (!otp.getOtpCode().equals(userInput)) {
                        log.warn("Invalid OTP entered for DID [{}]. Expected [{}], got [{}]", did, otp.getOtpCode(), userInput);
                        return false;
                    }

                    otp.setUsed(true);
                    otpRepository.save(otp);
                    log.info("OTP [{}] for DID [{}] verified successfully", otp.getOtpCode(), did);
                    return true;
                })
                .orElseGet(() -> {
                    log.warn("No active OTP found for DID [{}]", did);
                    return false;
                });
    }
}