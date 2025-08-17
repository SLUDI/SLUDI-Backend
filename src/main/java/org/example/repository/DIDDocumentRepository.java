package org.example.repository;

import org.example.entity.DIDDocument;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface DIDDocumentRepository extends JpaRepository<DIDDocument, String> {
    Optional<DIDDocument> findById(String id);
    boolean existsById(String id);
    void deleteById(String id);
}
