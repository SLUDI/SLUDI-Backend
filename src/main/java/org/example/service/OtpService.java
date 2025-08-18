package org.example.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.example.dto.OTP;
import org.example.entity.OtpEntity;
import org.example.repository.OtpRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Properties;

@Service
public class OtpService {

    private final JavaMailSender mailSender;

    @Autowired
    private OtpRepository otpRepository;

    private final SecureRandom random = new SecureRandom();

    @Value("${spring.mail.username}")
    private String senderEmail;

    @Value("${spring.mail.host}")
    private String mailHost;

    @Value("${spring.mail.port}")
    private int mailPort;

    @Value("${spring.mail.password}")
    private String mailPassword;

    @Value("${spring.mail.properties.mail.smtp.auth}")
    private boolean smtpAuth;

    @Value("${spring.mail.properties.mail.smtp.starttls.enable}")
    private boolean startTlsEnabled;

    @Value("${spring.mail.properties.mail.transport.protocol}")
    private String mailProtocol;

    public OtpService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    private JavaMailSender getJavaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(mailHost);
        mailSender.setPort(mailPort);

        mailSender.setUsername(senderEmail);
        mailSender.setPassword(mailPassword);

        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", mailProtocol);
        props.put("mail.smtp.auth", smtpAuth);
        props.put("mail.smtp.starttls.enable", startTlsEnabled);

        return mailSender;
    }

    public void sendOtpEmail(String toEmail, String otp) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);

        helper.setFrom(senderEmail);
        helper.setTo(toEmail);
        helper.setSubject("SLUDI - Your OTP Verification Code");

        String htmlContent = generateOtpEmailTemplate(otp);
        helper.setText(htmlContent, true);

        mailSender.send(message);
    }

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

    private String generateOtpEmailTemplate(String otp) {
        return """
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background-color: #f8f9fa; padding: 20px; text-align: center;">
                    <h1 style="color: #0d6efd;">SLUDI Digital Identity</h1>
                </div>
                <div style="padding: 20px;">
                    <h2>Email Verification</h2>
                    <p>Please use the following OTP to verify your email address:</p>
                    <div style="background-color: #e9ecef; padding: 15px; text-align: center; margin: 20px 0;">
                        <h1 style="color: #0d6efd; letter-spacing: 5px; margin: 0;">%s</h1>
                    </div>
                    <p>This OTP will expire in 5 minutes.</p>
                    <p>If you did not request this verification, please ignore this email.</p>
                </div>
                <div style="background-color: #f8f9fa; padding: 20px; text-align: center;">
                    <p style="color: #6c757d; margin: 0;">© 2025 SLUDI. All rights reserved.</p>
                </div>
            </div>
            """.formatted(otp);
    }

}