package org.example.repository;

import org.example.entity.PresentationRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PresentationRequestRepository extends JpaRepository<PresentationRequest, UUID> {

    Optional<PresentationRequest> findBySessionId(String sessionId);

    List<PresentationRequest> findByStatus(String status);

    List<PresentationRequest> findByCreatedBy(String userId);

    List<PresentationRequest> findByExpiresAtBeforeAndStatus(LocalDateTime dateTime, String status);

    Optional<PresentationRequest> findByIssuedCredentialId(String credentialId);
}
