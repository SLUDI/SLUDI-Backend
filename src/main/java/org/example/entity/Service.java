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
@Table(name = "services")
public class Service {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long internalId;

    private String id;
    private String type;

    @Column(name = "service_endpoint", length = 1000)
    private String serviceEndpoint;

    @ManyToOne
    @JoinColumn(name = "did_document_id", nullable = false)
    private DIDDocument didDocument;

    public Service(String id, String type, String serviceEndpoint) {
        this.id = id;
        this.type = type;
        this.serviceEndpoint = serviceEndpoint;
    }
}
