package org.example.repository;

import org.example.entity.CitizenUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface CitizenUserRepository extends JpaRepository<CitizenUser, UUID> {
    boolean existsByNic(String nic);
    boolean existsByEmail(String email);
    CitizenUser findByEmailOrNicOrDidId(String email, String nic, String didId);
}
