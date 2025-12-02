package org.example.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "public_keys")
@EqualsAndHashCode(exclude = {"internalId"})
public class PublicKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long internalId;

    private String id;
    private String type;
    private String controller;

    @Column(name = "public_keyStr", length = 1000)
    private String publicKeyBase58;

    @ManyToOne
    @JoinColumn(name = "did_document_id", nullable = false)
    private DIDDocument didDocument;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "citizen_user_id", nullable = false)
    private CitizenUser citizenUser;

    public PublicKey(String id, String type, String controller, String publicKeyBase58) {
        this.id = id;
        this.type = type;
        this.controller = controller;
        this.publicKeyBase58 = publicKeyBase58;
    }
}
