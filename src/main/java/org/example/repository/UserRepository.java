package org.example.repository;

import org.example.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    boolean existsByNic(String nic);
    boolean existsByEmail(String email);
    User findByEmailOrNicOrDidId(String email, String nic, String didId);
}
