package com.company.portal.service.secure;

import com.company.portal.dto.request.ScheduleRequest;
import com.company.portal.dto.response.ScheduleResponse;
import com.company.portal.entity.Employee;
import com.company.portal.entity.Team;
import com.company.portal.entity.TeamSchedule;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.exception.UnauthorizedException;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.repository.TeamRepository;
import com.company.portal.repository.TeamScheduleRepository;
import com.company.portal.util.SecurityUtil;
import com.company.portal.util.ValidationUtil;
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
public class SecureScheduleService {

    private final TeamScheduleRepository scheduleRepository;
    private final EmployeeRepository employeeRepository;
    private final TeamRepository teamRepository;
    private final ValidationUtil validationUtil;

    @Transactional
    public ScheduleResponse createSchedule(Long teamId, ScheduleRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee creator = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        Team team = teamRepository.findById(teamId)
                .orElseThrow(() -> new ResourceNotFoundException("팀을 찾을 수 없습니다"));

        // 팀 소속 확인
        if (creator.getTeam() == null || !creator.getTeam().getId().equals(teamId)) {
            throw new UnauthorizedException("해당 팀의 일정을 생성할 권한이 없습니다");
        }

        // XSS 방어
        String safeTitle = validationUtil.sanitizeInput(request.getTitle());
        String safeContent = validationUtil.sanitizeInput(request.getContent());

        Employee assignee = null;
        if (request.getAssigneeId() != null) {
            assignee = employeeRepository.findById(request.getAssigneeId())
                    .orElseThrow(() -> new ResourceNotFoundException("담당자를 찾을 수 없습니다"));
        }

        TeamSchedule schedule = TeamSchedule.builder()
                .team(team)
                .title(safeTitle)
                .content(safeContent)
                .startDate(request.getStartDate())
                .endDate(request.getEndDate())
                .assignee(assignee)
                .createdBy(creator)
                .build();

        TeamSchedule savedSchedule = scheduleRepository.save(schedule);

        log.info("Secure 모드 - 일정 생성 성공: team={}, schedule={}", teamId, savedSchedule.getId());

        return convertToResponse(savedSchedule);
    }

    @Transactional(readOnly = true)
    public List<ScheduleResponse> getTeamSchedules(Long teamId) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        // 팀 소속 확인
        if (employee.getTeam() == null || !employee.getTeam().getId().equals(teamId)) {
            throw new UnauthorizedException("해당 팀의 일정을 조회할 권한이 없습니다");
        }

        return scheduleRepository.findByTeamId(teamId).stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<ScheduleResponse> getTeamSchedulesByDateRange(Long teamId, LocalDateTime start, LocalDateTime end) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        // 팀 소속 확인
        if (employee.getTeam() == null || !employee.getTeam().getId().equals(teamId)) {
            throw new UnauthorizedException("해당 팀의 일정을 조회할 권한이 없습니다");
        }

        return scheduleRepository.findByTeamIdAndDateRange(teamId, start, end).stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    @Transactional
    public void deleteSchedule(Long id) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        TeamSchedule schedule = scheduleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("일정을 찾을 수 없습니다"));

        // 작성자 본인만 삭제 가능
        if (!schedule.getCreatedBy().getId().equals(currentEmployeeId)) {
            throw new UnauthorizedException("일정을 삭제할 권한이 없습니다");
        }

        scheduleRepository.delete(schedule);

        log.info("Secure 모드 - 일정 삭제 성공: {}", id);
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
