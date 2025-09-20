package org.example.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.util.Properties;

@Service
public class MailService {

    @Autowired
    private JavaMailSender mailSender;

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
