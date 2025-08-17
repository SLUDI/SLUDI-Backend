package org.example.entity;

import jakarta.persistence.*;
import jakarta.persistence.Table;
import lombok.*;

import java.util.List;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "did_documents")
public class DIDDocument {

    @Id
    private String id;

    private String didVersion;
    private String didCreated;
    private String didUpdated;

    @OneToMany(mappedBy = "didDocument", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    private List<PublicKey> publicKey;

    @ElementCollection
    @CollectionTable(name = "authentication", joinColumns = @JoinColumn(name = "did_id"))
    @Column(name = "auth_reference")
    private List<String> authentication;

    @OneToMany(mappedBy = "didDocument", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    private List<Services> services;

    private String status; // active, deactivated, revoked

    @Embedded
    private ProofData proof;
    private String blockchainTxId;
    private Long blockNumber;
}
