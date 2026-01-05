package com.company.portal.controller;

import com.company.portal.dto.request.ScheduleRequest;
import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.ScheduleResponse;
import com.company.portal.service.ScheduleService;
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

    private final ScheduleService scheduleService;

    @GetMapping("/api/schedules/all")
    public ResponseEntity<ApiResponse<List<ScheduleResponse>>> getAllSchedules() {
        List<ScheduleResponse> response = scheduleService.getAllSchedules();
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/api/teams/{teamId}/schedules")
    public ResponseEntity<ApiResponse<ScheduleResponse>> createSchedule(
            @PathVariable Long teamId,
            @Valid @RequestBody ScheduleRequest request) {

        ScheduleResponse response = scheduleService.createSchedule(teamId, request);
        return ResponseEntity.ok(ApiResponse.success("일정 생성 성공", response));
    }

    @GetMapping("/api/teams/{teamId}/schedules")
    public ResponseEntity<ApiResponse<List<ScheduleResponse>>> getTeamSchedules(@PathVariable Long teamId) {
        List<ScheduleResponse> response = scheduleService.getTeamSchedules(teamId);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/api/teams/{teamId}/schedules/range")
    public ResponseEntity<ApiResponse<List<ScheduleResponse>>> getTeamSchedulesByDateRange(
            @PathVariable Long teamId,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime start,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime end) {

        List<ScheduleResponse> response = scheduleService.getTeamSchedulesByDateRange(teamId, start, end);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @DeleteMapping("/api/teams/{teamId}/schedules/{scheduleId}")
    public ResponseEntity<ApiResponse<Void>> deleteSchedule(
            @PathVariable Long teamId,
            @PathVariable Long scheduleId) {

        scheduleService.deleteSchedule(scheduleId);
        return ResponseEntity.ok(ApiResponse.success("일정 삭제 성공", null));
    }
}
