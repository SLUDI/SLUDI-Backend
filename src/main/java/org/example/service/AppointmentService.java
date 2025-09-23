package org.example.service;

import jakarta.mail.MessagingException;
import org.example.dto.AppointmentDto;
import org.example.entity.Appointment;
import org.example.entity.CitizenUser;
import org.example.entity.UserPreferredDate;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.AppointmentRepository;
import org.example.repository.CitizenUserRepository;
import org.example.repository.UserPreferredDateRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class AppointmentService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AppointmentService.class);

    @Autowired
    private MailService mailService;

    @Autowired
    private CitizenUserRepository citizenUserRepository;

    @Autowired
    private UserPreferredDateRepository preferredDateRepository;

    @Autowired
    private AppointmentRepository appointmentRepository;

    private static final int MAX_APPOINTMENTS_PER_DAY = 5; // limit

    /**
     * Save exactly 3 preferred dates for a user.
     */
    public void savePreferredDates(UUID userId, List<LocalDate> dates) {
        LOGGER.info("Saving preferred dates for user: {}", userId);

        if (dates == null || dates.size() != 3) {
            throw new SludiException(ErrorCodes.INVALID_INPUT, "Exactly 3 dates must be provided");
        }

        CitizenUser user = citizenUserRepository.findById(userId)
                .orElseThrow(() -> {
                    LOGGER.error("User not found with ID: {}", userId);
                    return new SludiException(ErrorCodes.USER_NOT_FOUND, "User not found with ID: " + userId);
                });

        for (LocalDate date : dates) {
            boolean available = isDateAvailable(date);
            UserPreferredDate preferredDate = UserPreferredDate.builder()
                    .preferredDate(date.toString())
                    .available(available)
                    .citizenUser(user)
                    .build();

            preferredDateRepository.save(preferredDate);
        }

        LOGGER.info("Preferred dates saved successfully for user {}", userId);
    }

    /**
     * Check if a given date is available.
     */
    public boolean isDateAvailable(LocalDate date) {
        if (date == null) {
            throw new SludiException(ErrorCodes.INVALID_INPUT, "Date must not be null");
        }

        long count = appointmentRepository.countByConfirmedDate(date.toString());
        boolean available = count < MAX_APPOINTMENTS_PER_DAY;

        LOGGER.debug("Checked availability for date {}: {} ({} booked)", date, available, count);
        return available;
    }

    /**
     * Admin confirms one of the preferred dates -> creates appointment.
     */
    public AppointmentDto confirmAppointment(UUID userId, LocalDate confirmedDate) {
        LOGGER.info("Confirming appointment for user {} on date {}", userId, confirmedDate);

        if (confirmedDate == null) {
            throw new SludiException(ErrorCodes.INVALID_INPUT, "Confirmed date must not be null");
        }

        CitizenUser user = citizenUserRepository.findById(userId)
                .orElseThrow(() -> {
                    LOGGER.error("User not found with ID: {}", userId);
                    return new SludiException(ErrorCodes.USER_NOT_FOUND,
                            "User not found with ID: " + userId);
                });

        if (!isDateAvailable(confirmedDate)) {
            throw new SludiException(ErrorCodes.DATE_UNAVAILABLE,
                    "The date " + confirmedDate + " is not available for booking");
        }

        try {
            // Create and save appointment
            Appointment appointment = Appointment.builder()
                    .confirmedDate(confirmedDate.toString())
                    .status(Appointment.AppointmentStatus.CONFIRMED)
                    .citizenUser(user)
                    .build();

            Appointment savedAppointment = appointmentRepository.save(appointment);

            // Format date/time properly
            String dateTime = String.format("%s at 10:00 a.m.", confirmedDate);

            // Send confirmation email
            mailService.sendAppointmentEmail(
                    user.getEmail(),
                    user.getFullName(),
                    user.getAddress().getDivisionalSecretariat(),
                    dateTime,
                    user.getCitizenCode()
            );

            LOGGER.info("Appointment confirmed for user {} on {}", userId, confirmedDate);

            return AppointmentDto.builder()
                    .id(savedAppointment.getId())
                    .confirmedDate(LocalDate.parse(savedAppointment.getConfirmedDate()))
                    .status(savedAppointment.getStatus().toString())
                    .build();

        } catch (MessagingException e) {
            LOGGER.error("Failed to send appointment confirmation email for user {}: {}", userId, e.getMessage(), e);
            throw new SludiException(ErrorCodes.MAIL_SENDING_FAILED,
                    "Failed to send appointment confirmation email", e);
        } catch (Exception e) {
            LOGGER.error("Unexpected error while confirming appointment for user {}: {}", userId, e.getMessage(), e);
            throw new SludiException(ErrorCodes.INTERNAL_ERROR,
                    "Unexpected error occurred while confirming appointment", e);
        }
    }
}
