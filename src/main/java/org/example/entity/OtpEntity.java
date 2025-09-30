package org.example.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_otps")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OtpEntity {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(nullable = false)
    private String did;

    @Column(nullable = false)
    private String otpCode;

    @Column(nullable = false)
    private Instant expiryTime;

    @Column(nullable = false)
    private boolean used;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();
}
