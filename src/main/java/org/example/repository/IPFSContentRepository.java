package org.example.repository;

import org.example.entity.IPFSContent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface IPFSContentRepository extends JpaRepository<IPFSContent, UUID> {
    List<IPFSContent> findByOwnerUserId(UUID ownerUserId);
}
