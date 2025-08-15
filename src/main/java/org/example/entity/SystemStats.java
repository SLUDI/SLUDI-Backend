package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "system_statistics")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SystemStats {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private Integer totalDIDs;
    private Integer activeDIDs;
    private Integer deactivatedDIDs;
    private Integer revokedDIDs;
    private Integer totalCredentials;
    private Integer activeCredentials;
    private Integer revokedCredentials;
    private Integer suspendedCredentials;
    private Integer expiredCredentials;
    private Integer totalVerificationsToday;
    private Integer successfulVerificationsToday;
    private Integer failedVerificationsToday;
    private Integer totalRegistrationsToday;
    private Double networkHealthScore;
    private String timestamp;
    private Long blockchainHeight;

    public SystemStats(Integer totalDIDs, Integer activeDIDs, Integer totalCredentials,
                       Integer activeCredentials, Integer revokedCredentials, String timestamp) {
        this.totalDIDs = totalDIDs;
        this.activeDIDs = activeDIDs;
        this.totalCredentials = totalCredentials;
        this.activeCredentials = activeCredentials;
        this.revokedCredentials = revokedCredentials;
        this.timestamp = timestamp;
    }
}