package com.company.portal.controller;

import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.AttendanceResponse;
import com.company.portal.service.secure.SecureAttendanceService;
import com.company.portal.service.vulnerable.VulnerableAttendanceService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/attendance")
@RequiredArgsConstructor
public class AttendanceController {

    private final SecureAttendanceService secureAttendanceService;
    private final VulnerableAttendanceService vulnerableAttendanceService;

    @PostMapping("/check-in")
    public ResponseEntity<ApiResponse<AttendanceResponse>> checkIn(HttpServletRequest httpRequest) {
        String securityMode = (String) httpRequest.getAttribute("securityMode");

        AttendanceResponse response = "secure".equals(securityMode)
                ? secureAttendanceService.checkIn()
                : vulnerableAttendanceService.checkIn();

        return ResponseEntity.ok(ApiResponse.success("출근 처리 완료", response));
    }

    @PostMapping("/check-out")
    public ResponseEntity<ApiResponse<AttendanceResponse>> checkOut(HttpServletRequest httpRequest) {
        String securityMode = (String) httpRequest.getAttribute("securityMode");

        AttendanceResponse response = "secure".equals(securityMode)
                ? secureAttendanceService.checkOut()
                : vulnerableAttendanceService.checkOut();

        return ResponseEntity.ok(ApiResponse.success("퇴근 처리 완료", response));
    }

    @GetMapping("/my")
    public ResponseEntity<ApiResponse<List<AttendanceResponse>>> getMyAttendance(
            @RequestParam(required = false) Integer year,
            @RequestParam(required = false) Integer month,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        List<AttendanceResponse> response = "secure".equals(securityMode)
                ? secureAttendanceService.getMyAttendance(year, month)
                : vulnerableAttendanceService.getMyAttendance(year, month);

        return ResponseEntity.ok(ApiResponse.success("조회 성공", response));
    }

    @GetMapping("/today")
    public ResponseEntity<ApiResponse<AttendanceResponse>> getTodayAttendance(HttpServletRequest httpRequest) {
        String securityMode = (String) httpRequest.getAttribute("securityMode");

        AttendanceResponse response = "secure".equals(securityMode)
                ? secureAttendanceService.getTodayAttendance()
                : vulnerableAttendanceService.getTodayAttendance();

        return ResponseEntity.ok(ApiResponse.success("조회 성공", response));
    }

    @GetMapping("/admin/all")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<AttendanceResponse>>> getAllAttendance(
            @RequestParam(required = false) LocalDate date,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        List<AttendanceResponse> response = "secure".equals(securityMode)
                ? secureAttendanceService.getAllAttendance(date)
                : vulnerableAttendanceService.getAllAttendance(date);

        return ResponseEntity.ok(ApiResponse.success("조회 성공", response));
    }
}
