package org.example.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import java.util.Properties;

@Service
public class MailService {

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private TemplateEngine templateEngine;

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

    public void sendOtpEmail(String toEmail, String fullName, String otp) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setFrom(senderEmail);
        helper.setTo(toEmail);
        helper.setSubject("SLUDI - Your OTP Verification Code");

        // Thymeleaf context
        Context context = new Context();
        context.setVariable("fullName", fullName);
        context.setVariable("otp", otp);

        // Process template
        String htmlContent = templateEngine.process("otp-mail", context);
        helper.setText(htmlContent, true);

        // Embed logo + hero image
        ClassPathResource logo = new ClassPathResource("static/images/sludi-logo.png");
        ClassPathResource hero = new ClassPathResource("static/images/hero.png");
        helper.addInline("logoImage", logo);
        helper.addInline("heroImage", hero);

        // Send mail
        mailSender.send(message);
    }

    public void sendAppointmentEmail(String to,
                                     String fullName,
                                     String location,
                                     String dateTime,
                                     String referenceNumber) throws MessagingException {

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        // Prepare context for Thymeleaf
        Context context = new Context();
        context.setVariable("fullName", fullName);
        context.setVariable("location", location);
        context.setVariable("dateTime", dateTime);
        context.setVariable("referenceNumber", referenceNumber);

        // Process template
        String htmlContent = templateEngine.process("appointment-mail", context);

        // Email settings
        helper.setTo(to);
        helper.setSubject("Digital Identity Appointment Confirmation");
        helper.setText(htmlContent, true);

        // Embed images
        ClassPathResource logo = new ClassPathResource("static/images/sludi-logo.png");
        ClassPathResource hero = new ClassPathResource("static/images/hero.png");
        helper.addInline("logoImage", logo);
        helper.addInline("heroImage", hero);

        // Send email
        mailSender.send(message);
    }

}
