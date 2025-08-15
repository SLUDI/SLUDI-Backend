package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "public_keys")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PublicKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long internalId;

    private String id;
    private String type;
    private String controller;

    @Column(name = "public_key_base58", length = 1000)
    private String publicKeyBase58;

    @Column(name = "public_key_hex", length = 1000)
    private String publicKeyHex;

    @Column(name = "public_key_pem", length = 2000)
    private String publicKeyPem;

    private LocalDateTime createdAt;
    private Boolean isActive;

    public PublicKey(String id, String type, String controller, String publicKeyBase58) {
        this.id = id;
        this.type = type;
        this.controller = controller;
        this.publicKeyBase58 = publicKeyBase58;
        this.isActive = true;
        this.createdAt = LocalDateTime.now();
    }
}
