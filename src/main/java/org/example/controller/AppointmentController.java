package org.example.controller;

import org.example.dto.ApiResponseDto;
import org.example.dto.AppointmentDto;
import org.example.entity.Appointment;
import org.example.exception.SludiException;
import org.example.service.AppointmentService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

@RestController
@RequestMapping("/appointments")
@CrossOrigin(origins = "*")
public class AppointmentController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AppointmentController.class.getName());

    @Autowired
    private AppointmentService appointmentService;

    /**
     * Check availability of a given date
     * GET /api/appointments/check-availability
     */
    @GetMapping("/check-availability")
    public ResponseEntity<ApiResponseDto<Boolean>> checkAvailability(
            @RequestParam LocalDate date) {
        LOGGER.info("Received request to check availability for date={}", date);

        try {
            boolean isAvailable = appointmentService.isDateAvailable(date);

            ApiResponseDto<Boolean> response = ApiResponseDto.<Boolean>builder()
                    .success(true)
                    .message(isAvailable ? "Date is available" : "Date is not available")
                    .data(isAvailable)
                    .timestamp(Instant.now())
                    .build();

            LOGGER.info("Availability check completed for date={} -> {}", date, isAvailable);
            return ResponseEntity.ok(response);

        } catch (SludiException ex) {
            LOGGER.error("Business error while checking availability for date={}: {}", date, ex.getMessage(), ex);

            ApiResponseDto<Boolean> response = ApiResponseDto.<Boolean>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

        } catch (Exception ex) {
            LOGGER.error("Unexpected error while checking availability for date={}", date, ex);

            ApiResponseDto<Boolean> response = ApiResponseDto.<Boolean>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Confirm appointment for a user
     * POST /api/appointments/{userId}/confirm
     */
    @PostMapping("/{userId}/confirm")
    public ResponseEntity<ApiResponseDto<AppointmentDto>> confirmAppointment(
            @PathVariable UUID userId,
            @RequestParam LocalDate confirmedDate) {
        LOGGER.info("Received request to confirm appointment for userId={} on date={}", userId, confirmedDate);

        try {
            AppointmentDto appointment = appointmentService.confirmAppointment(userId, confirmedDate);

            ApiResponseDto<AppointmentDto> response = ApiResponseDto.<AppointmentDto>builder()
                    .success(true)
                    .message("Appointment confirmed successfully")
                    .data(appointment)
                    .timestamp(Instant.now())
                    .build();

            LOGGER.info("Appointment confirmed for userId={} on date={}", userId, confirmedDate);
            return ResponseEntity.ok(response);

        } catch (SludiException ex) {
            LOGGER.error("Business error while confirming appointment for userId={} on date={}: {}",
                    userId, confirmedDate, ex.getMessage(), ex);

            ApiResponseDto<AppointmentDto> response = ApiResponseDto.<AppointmentDto>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

        } catch (Exception ex) {
            LOGGER.error("Unexpected error while confirming appointment for userId={} on date={}", userId, confirmedDate, ex);

            ApiResponseDto<AppointmentDto> response = ApiResponseDto.<AppointmentDto>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}
