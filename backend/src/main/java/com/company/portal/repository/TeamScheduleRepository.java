package com.company.portal.repository;

import com.company.portal.entity.TeamSchedule;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface TeamScheduleRepository extends JpaRepository<TeamSchedule, Long> {

    List<TeamSchedule> findByTeamId(Long teamId);

    @Query("SELECT s FROM TeamSchedule s WHERE s.team.id = :teamId AND s.startDate >= :start AND s.endDate <= :end")
    List<TeamSchedule> findByTeamIdAndDateRange(
            @Param("teamId") Long teamId,
            @Param("start") LocalDateTime start,
            @Param("end") LocalDateTime end
    );
}
