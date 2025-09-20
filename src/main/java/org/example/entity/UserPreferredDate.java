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
@Table(name = "user_preferred_dates")
public class UserPreferredDate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private LocalDate preferredDate;

    private boolean available; // system-checked availability

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "citizen_user_id")
    private CitizenUser citizenUser;
}

