package org.example.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.example.dto.OTP;
import org.example.entity.OtpEntity;
import org.example.repository.OtpRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Service
@Transactional
public class OtpService {

    @Autowired
    private MailService mailService;

    @Autowired
    private OtpRepository otpRepository;

    private final SecureRandom random = new SecureRandom();

    // Generate a 6-digit OTP with expiry
    public OTP generateOTP(String did) {
        int expiryMinutes = 5; // OTP valid for 5 minutes
        int otp = 100000 + random.nextInt(900000);
        LocalDateTime expiryTime = LocalDateTime.now().plusMinutes(expiryMinutes);

        // Save in DB
        OtpEntity entity = OtpEntity.builder()
                .did(did)
                .otpCode(String.valueOf(otp))
                .expiryTime(expiryTime)
                .used(false)
                .build();
        otpRepository.save(entity);

        return new OTP(entity.getOtpCode(), expiryTime);
    }

    // Validate OTP
    public boolean verifyOTP(String did, String userInput) {
        return otpRepository.findTopByDidAndUsedFalseOrderByExpiryTimeDesc(did)
                .filter(otp -> !otp.getExpiryTime().isBefore(LocalDateTime.now()))
                .filter(otp -> otp.getOtpCode().equals(userInput))
                .map(otp -> {
                    otp.setUsed(true);
                    otpRepository.save(otp); // mark as used
                    return true;
                })
                .orElse(false);
    }

}