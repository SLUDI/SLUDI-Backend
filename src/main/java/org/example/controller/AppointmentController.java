package org.example.controller;

import lombok.extern.slf4j.Slf4j;
import org.example.dto.ApiResponseDto;
import org.example.dto.AppointmentAvailabilityResponseDto;
import org.example.dto.AppointmentDto;
import org.example.exception.SludiException;
import org.example.service.AppointmentService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/appointments")
@CrossOrigin(origins = "*")
public class AppointmentController {

    private final AppointmentService appointmentService;

    public AppointmentController(AppointmentService appointmentService) {
        this.appointmentService = appointmentService;
    }

    /**
     * Check availability of a given date
     * GET /api/appointments/check-availability
     */
    @GetMapping("/check-availability")
    public ResponseEntity<ApiResponseDto<Boolean>> checkAvailability(
            @RequestParam LocalDate date) {
        log.info("Received request to check availability for date={}", date);

        try {
            boolean isAvailable = appointmentService.isDateAvailable(date);

            ApiResponseDto<Boolean> response = ApiResponseDto.<Boolean>builder()
                    .success(true)
                    .message(isAvailable ? "Date is available" : "Date is not available")
                    .data(isAvailable)
                    .timestamp(Instant.now())
                    .build();

            log.info("Availability check completed for date={} -> {}", date, isAvailable);
            return ResponseEntity.ok(response);

        } catch (SludiException ex) {
            log.error("Business error while checking availability for date={}: {}", date, ex.getMessage(), ex);

            ApiResponseDto<Boolean> response = ApiResponseDto.<Boolean>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

        } catch (Exception ex) {
            log.error("Unexpected error while checking availability for date={}", date, ex);

            ApiResponseDto<Boolean> response = ApiResponseDto.<Boolean>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @GetMapping("/availability")
    public ResponseEntity<ApiResponseDto<List<AppointmentAvailabilityResponseDto>>> getDistrictAvailability(
            @RequestParam String district,
            @RequestParam(defaultValue = "15") int daysAhead) {

        log.info("Received request to get availability for district={} and daysAhead={}", district, daysAhead);

        try {
            List<AppointmentAvailabilityResponseDto> availability =
                    appointmentService.getDistrictAvailability(district, daysAhead);

            ApiResponseDto<List<AppointmentAvailabilityResponseDto>> response =
                    ApiResponseDto.<List<AppointmentAvailabilityResponseDto>>builder()
                            .success(true)
                            .message("Availability fetched successfully")
                            .data(availability)
                            .timestamp(Instant.now())
                            .build();

            log.info("Availability check completed for district={} -> {} days", district, daysAhead);
            return ResponseEntity.ok(response);

        } catch (SludiException ex) {
            log.error("Business error while fetching availability for district={}: {}", district, ex.getMessage(), ex);

            ApiResponseDto<List<AppointmentAvailabilityResponseDto>> response =
                    ApiResponseDto.<List<AppointmentAvailabilityResponseDto>>builder()
                            .success(false)
                            .message(ex.getMessage())
                            .errorCode(ex.getErrorCode())
                            .timestamp(Instant.now())
                            .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

        } catch (Exception ex) {
            log.error("Unexpected error while fetching availability for district={}", district, ex);

            ApiResponseDto<List<AppointmentAvailabilityResponseDto>> response =
                    ApiResponseDto.<List<AppointmentAvailabilityResponseDto>>builder()
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
    public ResponseEntity<ApiResponseDto<Boolean>> confirmAppointment(
            @PathVariable UUID userId,
            @RequestParam boolean documentsValid) {
        try {
            boolean isConformed = appointmentService.confirmAppointment(userId, documentsValid);

            ApiResponseDto<Boolean> response = ApiResponseDto.<Boolean>builder()
                    .success(true)
                    .message("Appointment confirmed successfully")
                    .data(isConformed)
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.ok(response);

        } catch (SludiException ex) {
            log.error("Business error while confirming appointment for userId={}", userId, ex);

            ApiResponseDto<Boolean> response = ApiResponseDto.<Boolean>builder()
                    .success(false)
                    .message(ex.getMessage())
                    .errorCode(ex.getErrorCode())
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

        } catch (Exception ex) {
            log.error("Unexpected error while confirming appointment for userId={}", userId, ex);

            ApiResponseDto<Boolean> response = ApiResponseDto.<Boolean>builder()
                    .success(false)
                    .message("Internal server error")
                    .errorCode("INTERNAL_ERROR")
                    .timestamp(Instant.now())
                    .build();

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}
