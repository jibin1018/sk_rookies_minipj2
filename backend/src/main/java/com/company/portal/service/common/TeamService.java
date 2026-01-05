package com.company.portal.service.common;

import com.company.portal.dto.response.TeamResponse;
import com.company.portal.entity.Team;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.repository.TeamRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class TeamService {

    private final TeamRepository teamRepository;

    public List<TeamResponse> getAllTeams() {
        return teamRepository.findAll()
                .stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    public TeamResponse getTeam(Long id) {
        Team team = teamRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("팀을 찾을 수 없습니다"));
        return toResponse(team);
    }

    public List<TeamResponse> getTeamsByDepartment(Long departmentId) {
        return teamRepository.findByDepartmentId(departmentId)
                .stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    /* =========================
       Entity → DTO 변환 메서드
       ========================= */
    private TeamResponse toResponse(Team team) {
        return TeamResponse.builder()
                .id(team.getId())
                .name(team.getName())
                .departmentId(
                        team.getDepartment() != null
                        ? team.getDepartment().getId()
                        : null
                )
                .departmentName(
                        team.getDepartment() != null
                        ? team.getDepartment().getName()
                        : null
                )
                .build();
    }
}
