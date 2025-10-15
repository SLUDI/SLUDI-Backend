package org.example.repository;

import org.example.entity.Appointment;
import org.example.entity.CitizenUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AppointmentRepository extends JpaRepository<Appointment, Long> {
    long countByConfirmedDate(String confirmedDate);
    long countByDistrictAndConfirmedDate(String district, String confirmedDate);
    Appointment findByCitizenUser(CitizenUser citizenUser);
}
