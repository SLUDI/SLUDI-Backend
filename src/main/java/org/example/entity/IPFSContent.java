package org.example.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "ipfs_contents")
public class IPFSContent {
    @Id
    private UUID id;

    private String ipfsHash;
    private UUID ownerUserId;
    private String category;
    private String subcategory;
    private String mimeType;
    private String accessLevel;
    private boolean isEncrypted;
    private String encryptionAlgorithm;
    private LocalDateTime uploadedAt;
}
