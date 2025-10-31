package org.example.repository;

import org.example.entity.CitizenUser;
import org.example.enums.UserStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface CitizenUserRepository extends JpaRepository<CitizenUser, UUID> {
    boolean existsByNicHash(String nicHash);
    boolean existsByEmailHash(String emailHash);
    @Query("SELECT c FROM CitizenUser c WHERE " +
            "(:emailHash IS NOT NULL AND c.emailHash = :emailHash) OR " +
            "(:nicHash IS NOT NULL AND c.nicHash = :nicHash) OR " +
            "(:didIdHash IS NOT NULL AND c.didIdHash = :didIdHash)")
    CitizenUser findByAnyHash(@Param("emailHash") String emailHash,
                              @Param("nicHash") String nicHash,
                              @Param("didIdHash") String didIdHash);

    boolean existsByDidId(String didId);
    long countByStatus(UserStatus userStatus);
}
