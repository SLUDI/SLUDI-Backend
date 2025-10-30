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
    boolean existsByNic(String nic);
    boolean existsByEmail(String email);
    @Query("SELECT c FROM CitizenUser c WHERE " +
            "(:email IS NOT NULL AND c.email = :email) OR " +
            "(:nic IS NOT NULL AND c.nic = :nic) OR " +
            "(:didId IS NOT NULL AND c.didId = :didId)")
    CitizenUser findByEmailOrNicOrDidId(@Param("email") String email,
                                        @Param("nic") String nic,
                                        @Param("didId") String didId);

    boolean existsByDidId(String didId);
    long countByStatus(UserStatus userStatus);
}
