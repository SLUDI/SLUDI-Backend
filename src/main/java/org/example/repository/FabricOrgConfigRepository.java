package org.example.repository;

import org.example.entity.FabricOrgConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FabricOrgConfigRepository extends JpaRepository<FabricOrgConfig, Long> {
    FabricOrgConfig findByMspId(String mspId);
    boolean existsByMspId(String mspId);
    default List<FabricOrgConfig> getAll() {
        return findAll();
    }
    List<FabricOrgConfig> findByIsAssignedFalse();
}
