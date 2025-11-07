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
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(user.getEmail());
            message.setSubject("Account Registration - Verification Required");
            message.setText(buildVerificationEmailContent(user));

            mailSender.send(message);
            log.info("Verification email sent successfully to: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send verification email to: " + user.getEmail(), e);
        }
    }

    /**
     * Send user activation email
     */
    public void sendUserActivationEmail(OrganizationUser user) {
        if (!emailEnabled) {
            log.info("Email disabled, skipping activation email for: {}", user.getEmail());
            return;
        }

        log.info("Sending activation email to: {}", user.getEmail());

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(user.getEmail());
            message.setSubject("Account Activated - Welcome to Digital Identity System");
            message.setText(buildActivationEmailContent(user));

            mailSender.send(message);
            log.info("Activation email sent successfully to: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send activation email to: " + user.getEmail(), e);
        }
    }

    /**
     * Send user suspension email
     */
    public void sendUserSuspensionEmail(OrganizationUser user, String reason) {
        if (!emailEnabled) {
            log.info("Email disabled, skipping suspension email for: {}", user.getEmail());
            return;
        }

        log.info("Sending suspension email to: {}", user.getEmail());

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(user.getEmail());
            message.setSubject("Account Suspended - Digital Identity System");
            message.setText(buildSuspensionEmailContent(user, reason));

            mailSender.send(message);
            log.info("Suspension email sent successfully to: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send suspension email to: " + user.getEmail(), e);
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
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(user.getEmail());
            message.setSubject("Account Reactivated - Digital Identity System");
            message.setText(buildReactivationEmailContent(user));

            mailSender.send(message);
            log.info("Reactivation email sent successfully to: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send reactivation email to: " + user.getEmail(), e);
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
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(user.getEmail());
            message.setSubject("Password Reset - Digital Identity System");
            message.setText(buildPasswordResetEmailContent(user, newPassword));

            mailSender.send(message);
            log.info("Password reset email sent successfully to: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send password reset email to: " + user.getEmail(), e);
        }
    }

    // Email content builders

    private String buildVerificationEmailContent(OrganizationUser user) {
        return String.format(
                "Dear %s %s,\n\n" +
                        "Your account has been created for %s.\n\n" +
                        "Account Details:\n" +
                        "- Username: %s\n" +
                        "- Employee ID: %s\n" +
                        "- Role: %s\n\n" +
                        "Your account is currently pending approval from an administrator.\n" +
                        "You will receive another email once your account is approved and activated.\n\n" +
                        "If you did not request this account, please contact your administrator immediately.\n\n" +
                        "Best regards,\n" +
                        "Digital Identity System Team",
                user.getFirstName(),
                user.getLastName(),
                user.getOrganization().getName(),
                user.getUsername(),
                user.getEmployeeId(),
                user.getAssignedRole().getRoleCode()
        );
    }

    private String buildActivationEmailContent(OrganizationUser user) {
        return String.format(
                "Dear %s %s,\n\n" +
                        "Great news! Your account has been approved and activated.\n\n" +
                        "You can now login to the Digital Identity System:\n" +
                        "- Login URL: %s/login\n" +
                        "- Username: %s\n\n" +
                        "Your Account Details:\n" +
                        "- Organization: %s\n" +
                        "- Role: %s\n" +
                        "- Department: %s\n" +
                        "- Employee ID: %s\n\n" +
                        "Your account has been enrolled on the blockchain network with ID: %s\n\n" +
                        "Assigned Permissions:\n%s\n\n" +
                        "For security reasons, please change your password after first login.\n\n" +
                        "Welcome to the team!\n\n" +
                        "Best regards,\n" +
                        "Digital Identity System Team",
                user.getFirstName(),
                user.getLastName(),
                baseUrl,
                user.getUsername(),
                user.getOrganization().getName(),
                user.getAssignedRole().getRoleCode(),
                user.getDepartment(),
                user.getEmployeeId(),
                user.getFabricUserId(),
                String.join("\n", user.getAssignedRole().getPermissions().stream()
                        .map(p -> "- " + p)
                        .toList())
        );
    }

    private String buildSuspensionEmailContent(OrganizationUser user, String reason) {
        return String.format(
                "Dear %s %s,\n\n" +
                        "Your account has been suspended.\n\n" +
                        "Reason: %s\n\n" +
                        "Your access to the Digital Identity System has been temporarily disabled.\n" +
                        "All blockchain operations associated with your account have been revoked.\n\n" +
                        "If you believe this is a mistake or would like to discuss this matter,\n" +
                        "please contact your administrator.\n\n" +
                        "Best regards,\n" +
                        "Digital Identity System Team",
                user.getFirstName(),
                user.getLastName(),
                reason
        );
    }

    private String buildReactivationEmailContent(OrganizationUser user) {
        return String.format(
                "Dear %s %s,\n\n" +
                        "Good news! Your account has been reactivated.\n\n" +
                        "You can now login again to the Digital Identity System:\n" +
                        "- Login URL: %s/login\n" +
                        "- Username: %s\n\n" +
                        "Your blockchain access has been restored.\n\n" +
                        "Best regards,\n" +
                        "Digital Identity System Team",
                user.getFirstName(),
                user.getLastName(),
                baseUrl,
                user.getUsername()
        );
    }

    private String buildPasswordResetEmailContent(OrganizationUser user, String newPassword) {
        return String.format(
                "Dear %s %s,\n\n" +
                        "Your password has been reset by an administrator.\n\n" +
                        "Your new temporary password is: %s\n\n" +
                        "IMPORTANT: Please login and change this password immediately.\n\n" +
                        "Login URL: %s/login\n" +
                        "Username: %s\n\n" +
                        "For security reasons, this temporary password should be changed as soon as possible.\n\n" +
                        "Best regards,\n" +
                        "Digital Identity System Team",
                user.getFirstName(),
                user.getLastName(),
                newPassword,
                baseUrl,
                user.getUsername()
        );
    }
}
