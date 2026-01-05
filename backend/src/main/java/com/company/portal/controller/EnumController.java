package com.company.portal.controller;

import com.company.portal.dto.response.ApiResponse;
import com.company.portal.enums.BoardCategory;
import com.company.portal.enums.Position;
import com.company.portal.enums.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/enums")
@RequiredArgsConstructor
public class EnumController {

    @GetMapping("/positions")
    public ResponseEntity<ApiResponse<List<Map<String, String>>>> getPositions() {
        List<Map<String, String>> positions = Arrays.stream(Position.values())
                .map(position -> Map.of(
                "value", position.name(),
                "label", position.getKorean()
        ))
                .collect(Collectors.toList());

        return ResponseEntity.ok(ApiResponse.success(positions));
    }

    @GetMapping("/roles")
    public ResponseEntity<ApiResponse<List<Map<String, String>>>> getRoles() {
        List<Map<String, String>> roles = Arrays.stream(Role.values())
                .map(role -> Map.of(
                "value", role.name(),
                "label", getRoleKorean(role)
        ))
                .collect(Collectors.toList());

        return ResponseEntity.ok(ApiResponse.success(roles));
    }

    @GetMapping("/board-categories")
    public ResponseEntity<ApiResponse<List<Map<String, String>>>> getBoardCategories() {
        List<Map<String, String>> categories = Arrays.stream(BoardCategory.values())
                .map(category -> Map.of(
                "value", category.name(),
                "label", category.getKorean()
        ))
                .collect(Collectors.toList());

        return ResponseEntity.ok(ApiResponse.success(categories));
    }

    private String getRoleKorean(Role role) {
        switch (role) {
            case USER:
                return "사원";
            case TEAM_LEADER:
                return "팀장";
            case MANAGER:
                return "부서장";
            case ADMIN:
                return "관리자";
            default:
                return role.name();
        }
    }
}
