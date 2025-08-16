package org.example.repository;

import org.example.entity.DIDDocument;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DIDDocumentRepository extends JpaRepository<DIDDocument, String> {
}
