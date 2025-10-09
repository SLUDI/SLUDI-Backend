package org.example.repository;

import org.example.entity.PublicKey;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PublicKeyRepository extends JpaRepository<PublicKey, Long> {
}
