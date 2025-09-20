package org.example.repository;

import org.example.entity.UserPreferredDate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface UserPreferredDateRepository extends JpaRepository<UserPreferredDate, Long> {
    List<UserPreferredDate> findByCitizenUserId(UUID userId);
}
