package org.example.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "services")
@EqualsAndHashCode(exclude = {"internalId"})
public class Services {

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

    public Services(String id, String type, String serviceEndpoint) {
        this.id = id;
        this.type = type;
        this.serviceEndpoint = serviceEndpoint;
    }
}
