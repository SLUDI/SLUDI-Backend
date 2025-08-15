package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "system_statistics")
public class SystemStats {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Integer totalDIDs;
    private Integer activeDIDs;

    private Integer totalCredentials;
    private Integer activeCredentials;
    private Integer revokedCredentials;

    private String timestamp;

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
