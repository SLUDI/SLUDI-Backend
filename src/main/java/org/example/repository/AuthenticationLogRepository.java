package org.example.repository;

import org.example.entity.AuthenticationLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface AuthenticationLogRepository extends JpaRepository<AuthenticationLog, UUID> {
}
