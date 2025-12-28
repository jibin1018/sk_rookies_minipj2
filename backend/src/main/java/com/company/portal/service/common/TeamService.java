package com.company.portal.service.common;

import com.company.portal.entity.Team;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.repository.TeamRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class TeamService {

    private final TeamRepository teamRepository;

    @Transactional(readOnly = true)
    public List<Team> getAllTeams() {
        return teamRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Team getTeam(Long id) {
        return teamRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("팀을 찾을 수 없습니다"));
    }

    @Transactional(readOnly = true)
    public List<Team> getTeamsByDepartment(Long departmentId) {
        return teamRepository.findByDepartmentId(departmentId);
    }
}
