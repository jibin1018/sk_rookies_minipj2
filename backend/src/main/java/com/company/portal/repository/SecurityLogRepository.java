package com.company.portal.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.company.portal.entity.SecurityLog;

@Repository
public interface SecurityLogRepository extends JpaRepository<SecurityLog, Long> {

    List<SecurityLog> findBySecurityMode(String securityMode);

    List<SecurityLog> findByAttackType(String attackType);

    Page<SecurityLog> findByCreatedAtBetween(LocalDateTime start, LocalDateTime end, Pageable pageable);

    @Query("SELECT s.attackType, COUNT(s) FROM SecurityLog s WHERE s.securityMode = :mode GROUP BY s.attackType")
    List<Object[]> getAttackStatsByMode(@Param("mode") String mode);
}
