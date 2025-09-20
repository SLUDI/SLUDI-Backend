package org.example.repository;

import org.example.entity.Appointment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;

@Repository
public interface AppointmentRepository extends JpaRepository<Appointment, Long> {
    long countByConfirmedDate(LocalDate confirmedDate);
}
