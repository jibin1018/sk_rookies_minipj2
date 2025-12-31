package com.company.portal.controller;

import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.DashboardSummaryResponse;
import com.company.portal.service.DashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
public class DashboardController {

    private final DashboardService dashboardService;

    @GetMapping("/summary")
    public ResponseEntity<ApiResponse<DashboardSummaryResponse>> getSummary() {
        return ResponseEntity.ok(
                ApiResponse.success(dashboardService.getDashboardSummary())
        );
    }
}
