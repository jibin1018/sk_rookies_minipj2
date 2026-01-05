package com.company.portal.repository;

import com.company.portal.entity.Attendance;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

@Repository
public interface AttendanceRepository extends JpaRepository<Attendance, Long> {

    List<Attendance> findByEmployeeIdAndWorkDateBetween(Long employeeId, LocalDate startDate, LocalDate endDate);

    Optional<Attendance> findByEmployeeIdAndWorkDate(Long employeeId, LocalDate workDate);

    // 특정 날짜의 모든 근태 조회
    List<Attendance> findByWorkDate(LocalDate workDate);

    // 팀별 근태 조회
    @Query("SELECT a FROM Attendance a WHERE a.employee.team.id = :teamId AND a.workDate = :workDate")
    List<Attendance> findByTeamIdAndWorkDate(@Param("teamId") Long teamId, @Param("workDate") LocalDate workDate);
}
