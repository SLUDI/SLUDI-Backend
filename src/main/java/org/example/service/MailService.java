package org.example.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Slf4j
@Service
public class MailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    @Value("${spring.mail.username}")
    private String senderEmail;

    public MailService(
            JavaMailSender mailSender,
            TemplateEngine templateEngine
    ) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
    }

    /**
     * Sends an OTP email to the given recipient.
     */
    public void sendOtpEmail(String toEmail, String fullName, String otp) {
        try {
            Context context = new Context();
            context.setVariable("fullName", fullName);
            context.setVariable("otp", otp);

            sendEmail(toEmail, "SLUDI - Your OTP Verification Code", "otp-mail", context);
            log.info("OTP email sent successfully to {}", toEmail);
        } catch (MessagingException e) {
            log.error("Failed to send OTP email to {}: {}", toEmail, e.getMessage(), e);
        }
    }

    /**
     * Sends an appointment confirmation email.
     */
    public void sendAppointmentEmail(String to,
                                     String fullName,
                                     String location,
                                     String dateTime,
                                     String referenceNumber) {
        try {
            Context context = new Context();
            context.setVariable("fullName", fullName);
            context.setVariable("location", location);
            context.setVariable("dateTime", dateTime);
            context.setVariable("referenceNumber", referenceNumber);

            sendEmail(to, "Digital Identity Appointment Confirmation", "appointment-mail", context);
            log.info("Appointment email sent successfully to {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send appointment email to {}: {}", to, e.getMessage(), e);
        }
    }

    /**
     * Utility method for sending templated emails.
     */
    private void sendEmail(String to, String subject, String templateName, Context context)
            throws MessagingException {

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setFrom(senderEmail);
        helper.setTo(to);
        helper.setSubject(subject);

        String htmlContent = templateEngine.process(templateName, context);
        helper.setText(htmlContent, true);

        mailSender.send(message);
    }
}
