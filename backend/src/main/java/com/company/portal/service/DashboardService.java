package com.company.portal.service;

import com.company.portal.dto.response.DashboardSummaryResponse;
import com.company.portal.entity.Employee;
import com.company.portal.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class DashboardService {

    private final CompanyBoardRepository companyBoardRepository;
    private final TeamScheduleRepository teamScheduleRepository;
    private final ApprovalRepository approvalRepository;
    private final SuggestionRepository suggestionRepository;
    private final EmployeeRepository employeeRepository;

    public DashboardSummaryResponse getDashboardSummary() {

        // ✅ 로그인 사용자
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String employeeId = authentication.getName();

        Employee employee = employeeRepository.findByEmployeeId(employeeId)
                .orElseThrow(() -> new IllegalStateException("로그인 사용자 정보 없음"));

        Long teamId = employee.getTeam() != null ? employee.getTeam().getId() : null;

        // 📅 이번 주 범위
        LocalDate today = LocalDate.now();
        LocalDate startOfWeekDate = today.with(DayOfWeek.MONDAY);
        LocalDate endOfWeekDate = today.with(DayOfWeek.SUNDAY);

        LocalDateTime startOfWeek = startOfWeekDate.atStartOfDay();
        LocalDateTime endOfWeek = endOfWeekDate.atTime(23, 59, 59);

        // 📰 사내 게시판 (전체 기준)
        long boardCount = companyBoardRepository.count();

        // 📅 팀 일정 (이번 주와 겹치는 일정)
        long weeklySchedule = 0;
        if (teamId != null) {
            weeklySchedule = teamScheduleRepository.countWeeklySchedules(
                    teamId,
                    startOfWeek,
                    endOfWeek
            );
        }

        // 📝 결재 대기 (본인이 결재자)
        long pendingApproval = approvalRepository.countPendingByApprover(employee.getId());

        // 💬 건의사항 (진행중)
        long suggestionCount = suggestionRepository.countByStatus("SUBMITTED");

        return DashboardSummaryResponse.builder()
                .boardCount(boardCount)
                .weeklySchedule(weeklySchedule)
                .pendingApproval(pendingApproval)
                .suggestionCount(suggestionCount)
                .build();
    }
}
