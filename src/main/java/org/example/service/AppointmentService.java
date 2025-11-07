package org.example.service;

import lombok.extern.slf4j.Slf4j;
import org.example.dto.AppointmentAvailabilityResponseDto;
import org.example.entity.Appointment;
import org.example.entity.CitizenUser;
import org.example.enums.AppointmentStatus;
import org.example.enums.VerificationStatus;
import org.example.enums.UserStatus;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.repository.AppointmentRepository;
import org.example.repository.CitizenUserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@Transactional
public class AppointmentService {

    private final MailService mailService;
    private final CitizenUserRepository citizenUserRepository;
    private final AppointmentRepository appointmentRepository;

    private static final int MAX_SLOTS_PER_DAY = 5; // limit

    public AppointmentService(
            MailService mailService,
            CitizenUserRepository citizenUserRepository,
            AppointmentRepository appointmentRepository
    ) {
        this.mailService = mailService;
        this.citizenUserRepository = citizenUserRepository;
        this.appointmentRepository = appointmentRepository;
    }

    /**
     * Save exactly preferred date for a user.
     */
    public void savePreferredDate(UUID userId, LocalDate date, String district) {
        log.info("Saving preferred dates for user: {}", userId);

        if (date == null ) {
            throw new SludiException(ErrorCodes.INVALID_INPUT, "Date must be provided");
        }

        CitizenUser user = citizenUserRepository.findById(userId)
                .orElseThrow(() -> {
                    log.error("User not found with ID: {}", userId);
                    return new SludiException(ErrorCodes.USER_NOT_FOUND, "User not found with ID: " + userId);
                });

        Appointment appointment = Appointment.builder()
                .district(district)
                .confirmedDate(date.toString())
                .status(AppointmentStatus.PENDING)
                .citizenUser(user)
                .build();

        appointmentRepository.save(appointment);

        log.info("Preferred date saved successfully for user {}", userId);
    }

    /**
     * Check if a given date is available.
     */
    public boolean isDateAvailable(LocalDate date) {
        if (date == null) {
            throw new SludiException(ErrorCodes.INVALID_INPUT, "Date must not be null");
        }

        long count = appointmentRepository.countByConfirmedDate(date.toString());
        boolean available = count < MAX_SLOTS_PER_DAY;

        log.debug("Checked availability for date {}: {} ({} booked)", date, available, count);
        return available;
    }

    public List<AppointmentAvailabilityResponseDto> getDistrictAvailability(String district, int daysAhead) {
        LocalDate today = LocalDate.now();
        LocalDate endDate = today.plusDays(daysAhead);

        List<AppointmentAvailabilityResponseDto> availabilityList = new ArrayList<>();

        for (LocalDate date = today; !date.isAfter(endDate); date = date.plusDays(1)) {
            String formattedDate = date.toString(); // e.g., "2025-10-10"

            long bookedCount = appointmentRepository.countByDistrictAndConfirmedDate(district, formattedDate);
            int availableSlots = (int) (MAX_SLOTS_PER_DAY - bookedCount);

            availabilityList.add(
                    new AppointmentAvailabilityResponseDto(
                            formattedDate,
                            Math.max(availableSlots, 0),
                            availableSlots <= 0
                    )
            );
        }

        return availabilityList;
    }

    /**
     * Admin confirms one of the preferred dates -> creates appointment.
     */
    public boolean confirmAppointment(UUID userId, boolean documentsValid) {
        try {
            CitizenUser user = citizenUserRepository.findById(userId)
                    .orElseThrow(() -> {
                        log.error("User not found with ID: {}", userId);
                        return new SludiException(ErrorCodes.USER_NOT_FOUND,
                                "User not found with ID: " + userId);
                    });

            if(documentsValid) {
                user.setStatus(UserStatus.PENDING);
                user.setVerificationStatus(VerificationStatus.IN_PROGRESS);

                citizenUserRepository.save(user);

                // Get saved appointment
                Appointment appointment = appointmentRepository.findByCitizenUser(user);

                // Format date/time properly
                String dateTime = String.format("%s at 10:00 a.m.", appointment.getConfirmedDate());

                // Send confirmation email
                mailService.sendAppointmentEmail(
                        user.getEmail(),
                        user.getFullName(),
                        user.getAddress().getDivisionalSecretariat(),
                        dateTime,
                        user.getCitizenCode()
                );

                log.info("Appointment confirmed for user {} on {}", userId, appointment.getConfirmedDate());

                return true;
            } else {
                user.setStatus(UserStatus.INACTIVE);
                user.setVerificationStatus(VerificationStatus.REJECTED);

                return false;
            }
        } catch (Exception e) {
            log.error("Unexpected error while confirming appointment for user {}: {}", userId, e.getMessage(), e);
            throw new SludiException(ErrorCodes.INTERNAL_ERROR,
                    "Unexpected error occurred while confirming appointment", e);
        }
    }
}
