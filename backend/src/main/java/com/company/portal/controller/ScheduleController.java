package com.company.portal.controller;

import com.company.portal.dto.request.ScheduleRequest;
import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.ScheduleResponse;
import com.company.portal.service.secure.SecureScheduleService;
import com.company.portal.service.vulnerable.VulnerableScheduleService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@RestController
@RequiredArgsConstructor
public class ScheduleController {

    private final SecureScheduleService secureScheduleService;
    private final VulnerableScheduleService vulnerableScheduleService;

    // 관리자용 - 모든 일정 조회 (새로 추가)
    @GetMapping("/api/schedules/all")
    public ResponseEntity<ApiResponse<List<ScheduleResponse>>> getAllSchedules(
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        List<ScheduleResponse> response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableScheduleService.getAllSchedules();
        } else {
            response = secureScheduleService.getAllSchedules();
        }

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/api/teams/{teamId}/schedules")
    public ResponseEntity<ApiResponse<ScheduleResponse>> createSchedule(
            @PathVariable Long teamId,
            @Valid @RequestBody ScheduleRequest request,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        ScheduleResponse response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableScheduleService.createSchedule(teamId, request);
        } else {
            response = secureScheduleService.createSchedule(teamId, request);
        }

        return ResponseEntity.ok(ApiResponse.success("일정 생성 성공", response));
    }

    @GetMapping("/api/teams/{teamId}/schedules")
    public ResponseEntity<ApiResponse<List<ScheduleResponse>>> getTeamSchedules(
            @PathVariable Long teamId,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        List<ScheduleResponse> response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableScheduleService.getTeamSchedules(teamId);
        } else {
            response = secureScheduleService.getTeamSchedules(teamId);
        }

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/api/teams/{teamId}/schedules/range")
    public ResponseEntity<ApiResponse<List<ScheduleResponse>>> getTeamSchedulesByDateRange(
            @PathVariable Long teamId,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        List<ScheduleResponse> response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableScheduleService.getTeamSchedulesByDateRange(teamId, start, end);
        } else {
            response = secureScheduleService.getTeamSchedulesByDateRange(teamId, start, end);
        }

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @DeleteMapping("/api/teams/{teamId}/schedules/{scheduleId}")
    public ResponseEntity<ApiResponse<Void>> deleteSchedule(
            @PathVariable Long teamId,
            @PathVariable Long scheduleId,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        if ("vulnerable".equals(securityMode)) {
            vulnerableScheduleService.deleteSchedule(scheduleId);
        } else {
            secureScheduleService.deleteSchedule(scheduleId);
        }

        return ResponseEntity.ok(ApiResponse.success("일정 삭제 성공", null));
    }
}
