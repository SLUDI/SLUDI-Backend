package org.example.repository;

import org.example.entity.OtpEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface OtpRepository extends JpaRepository<OtpEntity, UUID> {
    Optional<OtpEntity> findTopByDidAndUsedFalseOrderByExpiryTimeDesc(String did);

    Iterable<OtpEntity> findAllByDidAndUsedFalse(String did);
}
