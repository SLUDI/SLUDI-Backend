package org.example.repository;

import org.example.entity.VerifiableCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface VerifiableCredentialRepository extends JpaRepository<VerifiableCredential, String> {
    boolean existsById(String id);
    Optional<VerifiableCredential> findById(String id);
    List<VerifiableCredential> getAllBySubjectDid(String id);
    Optional<VerifiableCredential> findBySubjectDidAndCredentialType(String subjectDid, String credentialType);
}