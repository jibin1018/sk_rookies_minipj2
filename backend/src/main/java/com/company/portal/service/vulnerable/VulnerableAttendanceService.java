package com.company.portal.service.vulnerable;

import com.company.portal.dto.request.AttendanceRequest;
import com.company.portal.dto.response.AttendanceResponse;
import com.company.portal.entity.Attendance;
import com.company.portal.entity.Employee;
import com.company.portal.entity.SecurityLog;
import com.company.portal.enums.AttendanceStatus;
import com.company.portal.exception.BadRequestException;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.repository.AttendanceRepository;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.repository.SecurityLogRepository;
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
public class VulnerableAttendanceService {

    private final AttendanceRepository attendanceRepository;
    private final EmployeeRepository employeeRepository;
    private final SecurityLogRepository securityLogRepository;

    @Transactional
    public AttendanceResponse checkIn(AttendanceRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        LocalDate today = LocalDate.now();

        if (attendanceRepository.findByEmployeeIdAndWorkDate(currentEmployeeId, today).isPresent()) {
            throw new BadRequestException("이미 출근 처리되었습니다");
        }

        // 클라이언트에서 전송한 시간 사용 (Vulnerable - 조작 가능!)
        LocalDateTime checkInTime = request.getCheckIn() != null
                ? request.getCheckIn()
                : LocalDateTime.now();

        // 실제 시간과 비교
        LocalDateTime actualTime = LocalDateTime.now();
        if (!checkInTime.toLocalDate().equals(actualTime.toLocalDate())
                || Math.abs(java.time.Duration.between(checkInTime, actualTime).toMinutes()) > 60) {
            log.warn("Vulnerable 모드 - 출근 시간 조작 감지! claimed={}, actual={}", checkInTime, actualTime);
            logSecurityEvent("TIME_MANIPULATION",
                    "Check-in time manipulation detected: claimed=" + checkInTime + ", actual=" + actualTime);
        }

        LocalTime standardTime = LocalTime.of(9, 0);
        AttendanceStatus status = checkInTime.toLocalTime().isAfter(standardTime)
                ? AttendanceStatus.LATE
                : AttendanceStatus.PRESENT;

        Attendance attendance = Attendance.builder()
                .employee(employee)
                .workDate(today)
                .checkIn(checkInTime) // 조작된 시간 저장!
                .status(status)
                .build();

        Attendance savedAttendance = attendanceRepository.save(attendance);

        log.warn("Vulnerable 모드 - 출근 (시간 조작 가능): employee={}, time={}", currentEmployeeId, checkInTime);

        return convertToResponse(savedAttendance);
    }

    @Transactional
    public AttendanceResponse checkOut(AttendanceRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        LocalDate today = LocalDate.now();

        Attendance attendance = attendanceRepository.findByEmployeeIdAndWorkDate(currentEmployeeId, today)
                .orElseThrow(() -> new BadRequestException("출근 기록이 없습니다"));

        if (attendance.getCheckOut() != null) {
            throw new BadRequestException("이미 퇴근 처리되었습니다");
        }

        // 클라이언트에서 전송한 시간 사용 (Vulnerable)
        LocalDateTime checkOutTime = request.getCheckOut() != null
                ? request.getCheckOut()
                : LocalDateTime.now();

        LocalDateTime actualTime = LocalDateTime.now();
        if (Math.abs(java.time.Duration.between(checkOutTime, actualTime).toMinutes()) > 60) {
            log.warn("Vulnerable 모드 - 퇴근 시간 조작 감지!");
            logSecurityEvent("TIME_MANIPULATION",
                    "Check-out time manipulation: claimed=" + checkOutTime + ", actual=" + actualTime);
        }

        attendance.setCheckOut(checkOutTime);

        LocalTime standardTime = LocalTime.of(18, 0);
        if (checkOutTime.toLocalTime().isBefore(standardTime) && attendance.getStatus() == AttendanceStatus.PRESENT) {
            attendance.setStatus(AttendanceStatus.EARLY_LEAVE);
        }

        Attendance updatedAttendance = attendanceRepository.save(attendance);

        log.warn("Vulnerable 모드 - 퇴근 (시간 조작 가능): employee={}, time={}", currentEmployeeId, checkOutTime);

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
        // 권한 체크 없음 - 모든 사용자가 다른 팀 근태 조회 가능!
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        if (employee.getTeam() == null || !employee.getTeam().getId().equals(teamId)) {
            log.warn("Vulnerable 모드 - 권한 없는 팀 근태 조회!");
            logSecurityEvent("UNAUTHORIZED_ATTENDANCE_VIEW",
                    "Viewing other team's attendance: team=" + teamId + ", employee=" + currentEmployeeId);
        }

        return attendanceRepository.findByTeamIdAndWorkDate(teamId, date)
                .stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    private void logSecurityEvent(String attackType, String details) {
        SecurityLog securityLog = SecurityLog.builder()
                .attackType(attackType)
                .securityMode("vulnerable")
                .details(details)
                .build();

        securityLogRepository.save(securityLog);
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
