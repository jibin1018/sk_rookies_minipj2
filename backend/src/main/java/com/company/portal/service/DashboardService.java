package com.company.portal.service;

import com.company.portal.dto.response.DashboardSummaryResponse;
import com.company.portal.entity.*;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.repository.*;
import com.company.portal.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class DashboardService {

    private final EmployeeRepository employeeRepository;
    private final CompanyBoardRepository boardRepository;
    private final ApprovalRepository approvalRepository;
    private final SuggestionRepository suggestionRepository;
    private final TeamScheduleRepository teamScheduleRepository;

    @Transactional(readOnly = true)
    public DashboardSummaryResponse getDashboardSummary() {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        // 1. 사내 게시판 전체 글 수
        long boardCount = boardRepository.count();

        // 2. 팀 일정 수 (이번 주)
        Long teamId = employee.getTeam() != null ? employee.getTeam().getId() : null;
        long weeklyScheduleCount = 0L;
        List<DashboardSummaryResponse.WeeklySchedule> weeklySchedules = List.of();

        if (teamId != null) {
            LocalDate today = LocalDate.now();
            LocalDate startOfWeek = today.with(DayOfWeek.MONDAY);
            LocalDate endOfWeek = today.with(DayOfWeek.SUNDAY);

            LocalDateTime startDateTime = startOfWeek.atStartOfDay();
            LocalDateTime endDateTime = endOfWeek.atTime(23, 59, 59);

            // 이번 주 일정 개수
            weeklyScheduleCount = teamScheduleRepository.countWeeklySchedules(
                    teamId, startDateTime, endDateTime);

            // 이번 주 일정 리스트
            List<TeamSchedule> schedules = teamScheduleRepository.findWeeklySchedules(
                    teamId, startDateTime, endDateTime);

            weeklySchedules = schedules.stream()
                    .map(schedule -> DashboardSummaryResponse.WeeklySchedule.builder()
                    .id(schedule.getId())
                    .title(schedule.getTitle())
                    .date(schedule.getStartDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd")))
                    .time(schedule.getStartDate().format(DateTimeFormatter.ofPattern("HH:mm")))
                    .build())
                    .collect(Collectors.toList());
        }

        // 3. 내가 결재해야 할 문서 수
        long pendingApproval = approvalRepository.countPendingByApprover(employee.getId());

        // 4. 익명 건의함 전체 글 수
        long suggestionCount = suggestionRepository.count();

        // 5. 최근 공지사항 (최대 5개)
        List<CompanyBoard> notices = boardRepository.findTop5ByIsNoticeTrueOrderByCreatedAtDesc();
        List<DashboardSummaryResponse.RecentNotice> recentNotices = notices.stream()
                .map(notice -> DashboardSummaryResponse.RecentNotice.builder()
                .id(notice.getId())
                .title(notice.getTitle())
                .authorName(notice.getAuthor().getName())
                .createdAt(notice.getCreatedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd")))
                .build())
                .collect(Collectors.toList());

        log.info("대시보드 조회 완료 - 게시판: {}, 팀일정: {}, 결재대기: {}, 건의사항: {}",
                boardCount, weeklyScheduleCount, pendingApproval, suggestionCount);

        return DashboardSummaryResponse.builder()
                .boardCount(boardCount)
                .weeklySchedule(weeklyScheduleCount)
                .pendingApproval(pendingApproval)
                .suggestionCount(suggestionCount)
                .recentNotices(recentNotices)
                .weeklySchedules(weeklySchedules)
                .build();
    }
}
