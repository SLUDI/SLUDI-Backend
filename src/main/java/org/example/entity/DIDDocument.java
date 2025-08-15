package org.example.entity;

import jakarta.persistence.*;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "did_documents")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DIDDocument {

    @Id
    private String id;

    private String version;
    private String created;
    private String updated;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinColumn(name = "id")
    private List<PublicKey> publicKey;

    @ElementCollection
    @CollectionTable(name = "authentication", joinColumns = @JoinColumn(name = "did_id"))
    @Column(name = "auth_reference")
    private List<String> authentication;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinColumn(name = "id")
    private List<Service> service;

    private String status; // active, deactivated, revoked

    @Embedded
    private ProofData proof;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String blockchainTxId;
    private Long blockNumber;
}
