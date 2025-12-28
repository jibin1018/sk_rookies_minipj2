package com.company.portal.controller;

import com.company.portal.dto.request.AttendanceRequest;
import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.AttendanceResponse;
import com.company.portal.service.secure.SecureAttendanceService;
import com.company.portal.service.vulnerable.VulnerableAttendanceService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
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
    public ResponseEntity<ApiResponse<AttendanceResponse>> checkIn(
            @RequestBody(required = false) AttendanceRequest request,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        AttendanceResponse response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableAttendanceService.checkIn(request != null ? request : new AttendanceRequest());
        } else {
            response = secureAttendanceService.checkIn();
        }

        return ResponseEntity.ok(ApiResponse.success("출근 처리 성공", response));
    }

    @PostMapping("/check-out")
    public ResponseEntity<ApiResponse<AttendanceResponse>> checkOut(
            @RequestBody(required = false) AttendanceRequest request,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        AttendanceResponse response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableAttendanceService.checkOut(request != null ? request : new AttendanceRequest());
        } else {
            response = secureAttendanceService.checkOut();
        }

        return ResponseEntity.ok(ApiResponse.success("퇴근 처리 성공", response));
    }

    @GetMapping("/my")
    public ResponseEntity<ApiResponse<List<AttendanceResponse>>> getMyAttendances(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        List<AttendanceResponse> response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableAttendanceService.getMyAttendances(startDate, endDate);
        } else {
            response = secureAttendanceService.getMyAttendances(startDate, endDate);
        }

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/team/{teamId}")
    public ResponseEntity<ApiResponse<List<AttendanceResponse>>> getTeamAttendances(
            @PathVariable Long teamId,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        List<AttendanceResponse> response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableAttendanceService.getTeamAttendances(teamId, date);
        } else {
            response = secureAttendanceService.getTeamAttendances(teamId, date);
        }

        return ResponseEntity.ok(ApiResponse.success(response));
    }
}
