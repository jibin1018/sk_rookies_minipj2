package com.company.portal.service;

import com.company.portal.dto.response.DashboardSummaryResponse;
import com.company.portal.entity.Attendance;
import com.company.portal.entity.Employee;
import com.company.portal.enums.AttendanceStatus;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.repository.AttendanceRepository;
import com.company.portal.repository.CompanyBoardRepository;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.repository.ApprovalRepository;
import com.company.portal.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class DashboardService {

    private final EmployeeRepository employeeRepository;
    private final AttendanceRepository attendanceRepository;
    private final CompanyBoardRepository boardRepository;
    private final ApprovalRepository approvalRepository;

    @Transactional(readOnly = true)
    public DashboardSummaryResponse getDashboardSummary() {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        Long teamId = employee.getTeam() != null ? employee.getTeam().getId() : null;
        LocalDate today = LocalDate.now();

        long totalEmployees;
        long presentToday;
        long absentToday;
        long lateToday;

        if (teamId != null) {
            totalEmployees = employeeRepository.countByTeamId(teamId);
            List<Attendance> todayAttendance = attendanceRepository.findByWorkDate(today);

            presentToday = todayAttendance.stream()
                    .filter(a -> a.getStatus() == AttendanceStatus.PRESENT)
                    .count();

            absentToday = todayAttendance.stream()
                    .filter(a -> a.getStatus() == AttendanceStatus.ABSENT)
                    .count();

            lateToday = todayAttendance.stream()
                    .filter(a -> a.getStatus() == AttendanceStatus.LATE)
                    .count();
        } else {
            totalEmployees = 0;
            presentToday = 0;
            absentToday = 0;
            lateToday = 0;
        }

        long pendingApprovals = approvalRepository.countPendingByApprover(employee.getId());
        long unreadNotices = boardRepository.countByIsNoticeTrue();

        return DashboardSummaryResponse.builder()
                .totalEmployees(totalEmployees)
                .presentToday(presentToday)
                .absentToday(absentToday)
                .lateToday(lateToday)
                .pendingApprovals(pendingApprovals)
                .unreadNotices(unreadNotices)
                .build();
    }
}
