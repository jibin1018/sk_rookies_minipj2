package com.company.portal.controller;

import com.company.portal.dto.response.ApiResponse;
import com.company.portal.entity.Team;
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
    public ResponseEntity<ApiResponse<List<Team>>> getAllTeams() {
        List<Team> teams = teamService.getAllTeams();
        return ResponseEntity.ok(ApiResponse.success(teams));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<Team>> getTeam(@PathVariable Long id) {
        Team team = teamService.getTeam(id);
        return ResponseEntity.ok(ApiResponse.success(team));
    }

    @GetMapping("/department/{departmentId}")
    public ResponseEntity<ApiResponse<List<Team>>> getTeamsByDepartment(
            @PathVariable Long departmentId) {
        List<Team> teams = teamService.getTeamsByDepartment(departmentId);
        return ResponseEntity.ok(ApiResponse.success(teams));
    }
}
