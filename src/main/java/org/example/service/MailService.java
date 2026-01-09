package org.example.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.example.entity.OrganizationUser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.util.List;

@Slf4j
@Service
public class MailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    @Value("${app.email.from:noreply@identity.gov.lk}")
    private String fromEmail;

    @Value("${app.email.enabled:true}")
    private boolean emailEnabled;

    @Value("${app.base.url:http://localhost:8080}")
    private String baseUrl;

    @Value("${spring.mail.username}")
    private String senderEmail;

    public MailService(
            JavaMailSender mailSender,
            TemplateEngine templateEngine) {
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

    /**
     * Send user verification email
     */
    public void sendUserVerificationEmail(OrganizationUser user) {
        if (!emailEnabled) {
            log.info("Email disabled, skipping verification email for: {}", user.getEmail());
            return;
        }

        log.info("Sending verification email to: {}", user.getEmail());

        try {
            Context context = new Context();
            context.setVariable("firstName", user.getFirstName());
            context.setVariable("lastName", user.getLastName());
            context.setVariable("organizationName", user.getOrganization().getName());
            context.setVariable("username", user.getUsername());
            context.setVariable("employeeId", user.getEmployeeId());
            context.setVariable("role", user.getAssignedRole().getRoleCode());

            sendEmail(user.getEmail(),
                    "Account Registration - Verification Required",
                    "user-verification-mail",
                    context);

            log.info("Verification email sent successfully to: {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send verification email to {}: {}", user.getEmail(), e.getMessage(), e);
        }
    }

    /**
     * Sends user activation email
     */
    public void sendUserActivationEmail(OrganizationUser user) {
        if (!emailEnabled) {
            log.info("Email disabled, skipping activation email for: {}", user.getEmail());
            return;
        }

        log.info("Sending activation email to: {}", user.getEmail());

        try {
            Context context = new Context();
            context.setVariable("firstName", user.getFirstName());
            context.setVariable("lastName", user.getLastName());
            context.setVariable("organizationName", user.getOrganization().getName());
            context.setVariable("department", user.getDepartment());
            context.setVariable("role", user.getAssignedRole().getRoleCode());
            context.setVariable("employeeId", user.getEmployeeId());
            context.setVariable("fabricUserId", user.getFabricUserId());
            context.setVariable("username", user.getUsername());
            context.setVariable("loginUrl", baseUrl + "/login");

            // Convert permissions list to a readable format
            List<String> permissions = user.getAssignedRole().getPermissions().stream()
                    .map(p -> p.startsWith("-") ? p : "- " + p)
                    .toList();

            context.setVariable("permissions", permissions);

            sendEmail(
                    user.getEmail(),
                    "Account Activated - Welcome to Digital Identity System",
                    "user-activation-mail",
                    context);

            log.info("Activation email sent successfully to: {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send activation email to {}: {}", user.getEmail(), e.getMessage(), e);
        }
    }

    /**
     * Sends user suspension email
     */
    public void sendUserSuspensionEmail(OrganizationUser user, String reason) {
        if (!emailEnabled) {
            log.info("Email disabled, skipping suspension email for: {}", user.getEmail());
            return;
        }

        log.info("Sending suspension email to: {}", user.getEmail());

        try {
            Context context = new Context();
            context.setVariable("firstName", user.getFirstName());
            context.setVariable("lastName", user.getLastName());
            context.setVariable("reason", reason);

            sendEmail(
                    user.getEmail(),
                    "Account Suspended - Digital Identity System",
                    "user-suspension-mail",
                    context);

            log.info("Suspension email sent successfully to: {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send suspension email to {}: {}", user.getEmail(), e.getMessage(), e);
        }
    }

    /**
     * Send user reactivation email
     */
    public void sendUserReactivationEmail(OrganizationUser user) {
        if (!emailEnabled) {
            log.info("Email disabled, skipping reactivation email for: {}", user.getEmail());
            return;
        }

        log.info("Sending reactivation email to: {}", user.getEmail());

        try {
            Context context = new Context();
            context.setVariable("firstName", user.getFirstName());
            context.setVariable("lastName", user.getLastName());
            context.setVariable("loginUrl", baseUrl + "/login");
            context.setVariable("username", user.getUsername());

            sendEmail(
                    user.getEmail(),
                    "Account Reactivated - Digital Identity System",
                    "user-reactivation-mail",
                    context);

            log.info("Reactivation email sent successfully to: {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send reactivation email to {}: {}", user.getEmail(), e.getMessage(), e);
        }
    }

    /**
     * Send password reset email
     */
    public void sendPasswordResetEmail(OrganizationUser user, String newPassword) {
        if (!emailEnabled) {
            log.info("Email disabled, skipping password reset email for: {}", user.getEmail());
            return;
        }

        log.info("Sending password reset email to: {}", user.getEmail());

        try {
            Context context = new Context();
            context.setVariable("firstName", user.getFirstName());
            context.setVariable("lastName", user.getLastName());
            context.setVariable("newPassword", newPassword);
            context.setVariable("loginUrl", baseUrl + "/login");
            context.setVariable("username", user.getUsername());

            sendEmail(
                    user.getEmail(),
                    "Password Reset - Digital Identity System",
                    "password-reset-mail",
                    context);

            log.info("Password reset email sent successfully to: {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send password reset email to {}: {}", user.getEmail(), e.getMessage(), e);
        }
    }
}
