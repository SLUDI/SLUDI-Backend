package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "appointments")
public class Appointment {

    public enum AppointmentStatus { PENDING, CONFIRMED, COMPLETED, CANCELLED }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private LocalDate confirmedDate;

    @Enumerated(EnumType.STRING)
    private AppointmentStatus status;

    @OneToOne
    @JoinColumn(name = "citizen_user_id")
    private CitizenUser citizenUser;
}

