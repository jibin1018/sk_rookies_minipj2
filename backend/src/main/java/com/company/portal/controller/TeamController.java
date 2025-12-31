package com.company.portal.controller;

import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.TeamResponse;
import com.company.portal.service.common.TeamService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/teams")
@RequiredArgsConstructor
public class TeamController {

    private final TeamService teamService;

    @GetMapping
    public ResponseEntity<ApiResponse<List<TeamResponse>>> getAllTeams() {
        return ResponseEntity.ok(
                ApiResponse.success(teamService.getAllTeams())
        );
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<TeamResponse>> getTeam(@PathVariable Long id) {
        return ResponseEntity.ok(
                ApiResponse.success(teamService.getTeam(id))
        );
    }

    @GetMapping("/department/{departmentId}")
    public ResponseEntity<ApiResponse<List<TeamResponse>>> getTeamsByDepartment(
            @PathVariable Long departmentId) {

        return ResponseEntity.ok(
                ApiResponse.success(teamService.getTeamsByDepartment(departmentId))
        );
    }
}
