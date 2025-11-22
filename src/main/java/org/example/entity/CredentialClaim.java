package org.example.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "credential_claims")
public class CredentialClaim {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String claimName;

    @Column(columnDefinition = "TEXT")
    private String claimHash;

    @ManyToOne
    @JoinColumn(name = "credential_id")
    private VerifiableCredential credential;
}
