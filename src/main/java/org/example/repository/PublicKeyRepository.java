package org.example.repository;

import org.example.entity.CitizenUser;
import org.example.entity.PublicKey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PublicKeyRepository extends JpaRepository<PublicKey, Long> {
    PublicKey findByCitizenUser(CitizenUser citizenUser);

    List<PublicKey> findAllByCitizenUser(CitizenUser citizenUser);
}
