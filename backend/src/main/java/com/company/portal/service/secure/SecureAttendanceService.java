package com.company.portal.service.secure;

import com.company.portal.dto.request.AttendanceRequest;
import com.company.portal.dto.response.AttendanceResponse;
import com.company.portal.entity.Attendance;
import com.company.portal.entity.Employee;
import com.company.portal.enums.AttendanceStatus;
import com.company.portal.exception.BadRequestException;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.exception.UnauthorizedException;
import com.company.portal.repository.AttendanceRepository;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecureAttendanceService {

    private final AttendanceRepository attendanceRepository;
    private final EmployeeRepository employeeRepository;

    @Transactional
    public AttendanceResponse checkIn() {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        LocalDate today = LocalDate.now();

        // 이미 출근한 경우
        if (attendanceRepository.findByEmployeeIdAndWorkDate(currentEmployeeId, today).isPresent()) {
            throw new BadRequestException("이미 출근 처리되었습니다");
        }

        // 서버 시간 사용 (Secure)
        LocalDateTime now = LocalDateTime.now();
        LocalTime standardTime = LocalTime.of(9, 0);

        AttendanceStatus status = now.toLocalTime().isAfter(standardTime)
                ? AttendanceStatus.LATE
                : AttendanceStatus.PRESENT;

        Attendance attendance = Attendance.builder()
                .employee(employee)
                .workDate(today)
                .checkIn(now)
                .status(status)
                .build();

        Attendance savedAttendance = attendanceRepository.save(attendance);

        log.info("Secure 모드 - 출근 성공: employee={}, time={}", currentEmployeeId, now);

        return convertToResponse(savedAttendance);
    }

    @Transactional
    public AttendanceResponse checkOut() {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        LocalDate today = LocalDate.now();

        Attendance attendance = attendanceRepository.findByEmployeeIdAndWorkDate(currentEmployeeId, today)
                .orElseThrow(() -> new BadRequestException("출근 기록이 없습니다"));

        if (attendance.getCheckOut() != null) {
            throw new BadRequestException("이미 퇴근 처리되었습니다");
        }

        // 서버 시간 사용 (Secure)
        LocalDateTime now = LocalDateTime.now();
        attendance.setCheckOut(now);

        // 조퇴 확인
        LocalTime standardTime = LocalTime.of(18, 0);
        if (now.toLocalTime().isBefore(standardTime) && attendance.getStatus() == AttendanceStatus.PRESENT) {
            attendance.setStatus(AttendanceStatus.EARLY_LEAVE);
        }

        Attendance updatedAttendance = attendanceRepository.save(attendance);

        log.info("Secure 모드 - 퇴근 성공: employee={}, time={}", currentEmployeeId, now);

        return convertToResponse(updatedAttendance);
    }

    @Transactional(readOnly = true)
    public List<AttendanceResponse> getMyAttendances(LocalDate startDate, LocalDate endDate) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        return attendanceRepository.findByEmployeeIdAndWorkDateBetween(currentEmployeeId, startDate, endDate)
                .stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<AttendanceResponse> getTeamAttendances(Long teamId, LocalDate date) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        // 팀장만 조회 가능
        if (employee.getTeam() == null
                || !employee.getTeam().getId().equals(teamId)
                || employee.getRole().name().equals("USER")) {
            throw new UnauthorizedException("팀원 근태를 조회할 권한이 없습니다");
        }

        return attendanceRepository.findByTeamIdAndWorkDate(teamId, date)
                .stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    private AttendanceResponse convertToResponse(Attendance attendance) {
        return AttendanceResponse.builder()
                .id(attendance.getId())
                .employeeName(attendance.getEmployee().getName())
                .workDate(attendance.getWorkDate())
                .checkIn(attendance.getCheckIn())
                .checkOut(attendance.getCheckOut())
                .status(attendance.getStatus())
                .note(attendance.getNote())
                .build();
    }
}
