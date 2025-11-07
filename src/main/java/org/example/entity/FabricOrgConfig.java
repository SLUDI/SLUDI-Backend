package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "fabric_config")
public class FabricOrgConfig {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String chainCodeName;
    private String channelName;
    private String mspId;
    private String peerEndpoint;
    private String caEndpoint;
    private String ordererEndpoint;
    private String cryptoPath;
    private String walletPath;
    private Boolean isAssigned;
}
