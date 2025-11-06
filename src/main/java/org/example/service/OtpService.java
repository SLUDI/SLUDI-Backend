package org.example.service;

import lombok.extern.slf4j.Slf4j;
import org.example.dto.OTP;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class OtpService {

    private static final String REDIS_KEY_PREFIX = "otp:did:";
    private static final int OTP_LENGTH = 6;
    private static final long EXPIRY_MINUTES = 5L;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final StringRedisTemplate redisTemplate;

    public OtpService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Generate a 6-digit OTP and store it in Redis.
     * Only ONE active OTP per DID at a time.
     */
    public OTP generateOTP(String did) {
        String otpCode = generateSixDigitCode();
        Instant expiresAt = Instant.now().plus(EXPIRY_MINUTES, ChronoUnit.MINUTES);

        String key = redisKey(did);

        redisTemplate.opsForValue().set(
                key,
                otpCode + ":" + expiresAt.toEpochMilli(),
                EXPIRY_MINUTES,
                TimeUnit.MINUTES
        );

        log.info("Generated OTP [{}] for DID [{}], expires at [{}]", otpCode, did, expiresAt);
        return new OTP(otpCode, expiresAt);
    }

    /**
     * Verify OTP. Returns true only if:
     * - OTP exists
     * - Not expired
     * - Matches user input
     * On success → delete the OTP (mark as used)
     */
    public boolean verifyOTP(String did, String userInput) {
        String key = redisKey(did);
        String stored = redisTemplate.opsForValue().get(key);

        if (stored == null) {
            log.warn("No active OTP found for DID [{}]", did);
            return false;
        }

        String[] parts = stored.split(":", 2);
        if (parts.length != 2) {
            log.error("Corrupted OTP data in Redis for key [{}]", key);
            redisTemplate.delete(key);
            return false;
        }

        String storedCode = parts[0];
        long expiryMillis;
        try {
            expiryMillis = Long.parseLong(parts[1]);
        } catch (NumberFormatException e) {
            log.error("Invalid expiry timestamp in Redis for key [{}]", key);
            redisTemplate.delete(key);
            return false;
        }

        Instant expiry = Instant.ofEpochMilli(expiryMillis);

        // Check expiry
        if (Instant.now().isAfter(expiry)) {
            log.warn("OTP for DID [{}] has expired", did);
            redisTemplate.delete(key);
            return false;
        }

        // Check code match
        if (!storedCode.equals(userInput)) {
            log.warn("Invalid OTP entered for DID [{}]. Expected [{}], got [{}]", did, storedCode, userInput);
            return false;
        }

        // Mark as used → delete
        redisTemplate.delete(key);
        log.info("OTP [{}] for DID [{}] verified and consumed", storedCode, did);
        return true;
    }

    private String redisKey(String did) {
        return REDIS_KEY_PREFIX + did;
    }

    private String generateSixDigitCode() {
        int otp = 100_000 + RANDOM.nextInt(900_000);
        return String.valueOf(otp);
    }
}