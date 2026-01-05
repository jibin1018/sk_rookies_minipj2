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

    // ✅ ScheduleService 용
    List<TeamSchedule> findByTeamId(Long teamId);

    // ✅ ScheduleService 용
    @Query("""
        SELECT s
        FROM TeamSchedule s
        WHERE s.team.id = :teamId
          AND s.startDate >= :start
          AND s.endDate <= :end
    """)
    List<TeamSchedule> findByTeamIdAndDateRange(
            @Param("teamId") Long teamId,
            @Param("start") LocalDateTime start,
            @Param("end") LocalDateTime end
    );

    // ✅ Dashboard용
    @Query("""
        SELECT COUNT(s)
        FROM TeamSchedule s
        WHERE s.team.id = :teamId
          AND s.startDate <= :end
          AND s.endDate >= :start
    """)
    long countWeeklySchedules(
            @Param("teamId") Long teamId,
            @Param("start") LocalDateTime start,
            @Param("end") LocalDateTime end
    );

    // ✅ Dashboard용 - 이번 주 일정 리스트
    @Query("""
        SELECT s
        FROM TeamSchedule s
        WHERE s.team.id = :teamId
          AND s.startDate <= :end
          AND s.endDate >= :start
        ORDER BY s.startDate ASC
    """)
    List<TeamSchedule> findWeeklySchedules(
            @Param("teamId") Long teamId,
            @Param("start") LocalDateTime start,
            @Param("end") LocalDateTime end
    );
}
