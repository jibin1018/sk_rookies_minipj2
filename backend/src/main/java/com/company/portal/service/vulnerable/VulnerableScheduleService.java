package com.company.portal.service.vulnerable;

import com.company.portal.dto.request.ScheduleRequest;
import com.company.portal.dto.response.ScheduleResponse;
import com.company.portal.entity.Employee;
import com.company.portal.entity.SecurityLog;
import com.company.portal.entity.Team;
import com.company.portal.entity.TeamSchedule;
import com.company.portal.enums.Role;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.repository.SecurityLogRepository;
import com.company.portal.repository.TeamRepository;
import com.company.portal.repository.TeamScheduleRepository;
import com.company.portal.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class VulnerableScheduleService {

    private final TeamScheduleRepository scheduleRepository;
    private final EmployeeRepository employeeRepository;
    private final TeamRepository teamRepository;
    private final SecurityLogRepository securityLogRepository;

    @Transactional
    public ScheduleResponse createSchedule(Long teamId, ScheduleRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee creator = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        Team team = teamRepository.findById(teamId)
                .orElseThrow(() -> new ResourceNotFoundException("팀을 찾을 수 없습니다"));

        // 팀 소속 확인 없음 - 다른 팀 일정도 생성 가능!
        if (creator.getTeam() == null || !creator.getTeam().getId().equals(teamId)) {
            log.warn("Vulnerable 모드 - 권한 없는 일정 생성 성공!");
            logSecurityEvent("UNAUTHORIZED_SCHEDULE_CREATE",
                    "Unauthorized schedule creation: team=" + teamId + ", employee=" + currentEmployeeId);
        }

        // XSS 취약점
        String title = request.getTitle();
        String content = request.getContent();

        if (title.contains("<script")) {
            logSecurityEvent("XSS_SCHEDULE", "XSS payload in schedule: " + title);
        }

        Employee assignee = null;
        if (request.getAssigneeId() != null) {
            assignee = employeeRepository.findById(request.getAssigneeId())
                    .orElseThrow(() -> new ResourceNotFoundException("담당자를 찾을 수 없습니다"));
        }

        TeamSchedule schedule = TeamSchedule.builder()
                .team(team)
                .title(title)
                .content(content)
                .startDate(request.getStartDate())
                .endDate(request.getEndDate())
                .assignee(assignee)
                .createdBy(creator)
                .build();

        TeamSchedule savedSchedule = scheduleRepository.save(schedule);

        log.warn("Vulnerable 모드 - 일정 생성 (권한 체크 없음): {}", savedSchedule.getId());

        return convertToResponse(savedSchedule);
    }

    @Transactional(readOnly = true)
    public List<ScheduleResponse> getTeamSchedules(Long teamId) {
        // 팀 소속 확인 없음 - 모든 팀 일정 조회 가능!
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        if (employee.getTeam() == null || !employee.getTeam().getId().equals(teamId)) {
            log.warn("Vulnerable 모드 - 권한 없는 팀 일정 조회!");
            logSecurityEvent("UNAUTHORIZED_SCHEDULE_VIEW",
                    "Viewing other team's schedule: team=" + teamId + ", employee=" + currentEmployeeId);
        }

        return scheduleRepository.findByTeamId(teamId).stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<ScheduleResponse> getTeamSchedulesByDateRange(Long teamId, LocalDateTime start, LocalDateTime end) {
        return scheduleRepository.findByTeamIdAndDateRange(teamId, start, end).stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<ScheduleResponse> getAllSchedules() {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        // Enum 비교로 수정
        if (employee.getRole() != Role.ADMIN) {
            log.warn("Vulnerable 모드 - 비관리자가 모든 일정 조회!");
            logSecurityEvent("UNAUTHORIZED_ALL_SCHEDULE_VIEW",
                    "Non-admin viewing all schedules: employee=" + currentEmployeeId);
        }

        return scheduleRepository.findAll().stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    @Transactional
    public void deleteSchedule(Long id) {
        TeamSchedule schedule = scheduleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("일정을 찾을 수 없습니다"));

        // 권한 체크 없음 - 누구나 삭제 가능!
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        if (!schedule.getCreatedBy().getId().equals(currentEmployeeId)) {
            log.warn("Vulnerable 모드 - 권한 없는 일정 삭제 성공!");
            logSecurityEvent("UNAUTHORIZED_SCHEDULE_DELETE",
                    "Unauthorized schedule deletion: schedule=" + id);
        }

        scheduleRepository.delete(schedule);

        log.warn("Vulnerable 모드 - 일정 삭제 (권한 체크 없음): {}", id);
    }

    private void logSecurityEvent(String attackType, String details) {
        SecurityLog securityLog = SecurityLog.builder()
                .attackType(attackType)
                .securityMode("vulnerable")
                .details(details)
                .build();

        securityLogRepository.save(securityLog);
    }

    private ScheduleResponse convertToResponse(TeamSchedule schedule) {
        return ScheduleResponse.builder()
                .id(schedule.getId())
                .title(schedule.getTitle())
                .content(schedule.getContent())
                .startDate(schedule.getStartDate())
                .endDate(schedule.getEndDate())
                .assigneeName(schedule.getAssignee() != null ? schedule.getAssignee().getName() : null)
                .assigneeId(schedule.getAssignee() != null ? schedule.getAssignee().getId() : null)
                .createdByName(schedule.getCreatedBy().getName())
                .createdAt(schedule.getCreatedAt())
                .build();
    }
}
