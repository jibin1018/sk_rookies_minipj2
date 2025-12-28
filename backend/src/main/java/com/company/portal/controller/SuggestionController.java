package com.company.portal.controller;

import com.company.portal.dto.request.SuggestionRequest;
import com.company.portal.dto.response.ApiResponse;
import com.company.portal.entity.Suggestion;
import com.company.portal.service.common.SuggestionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/suggestions")
@RequiredArgsConstructor
public class SuggestionController {

    private final SuggestionService suggestionService;

    @PostMapping
    public ResponseEntity<ApiResponse<Suggestion>> createSuggestion(
            @Valid @RequestBody SuggestionRequest request) {
        Suggestion suggestion = suggestionService.createSuggestion(request);
        return ResponseEntity.ok(ApiResponse.success("건의사항 작성 성공", suggestion));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<Page<Suggestion>>> getAllSuggestions(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<Suggestion> suggestions = suggestionService.getAllSuggestions(pageable);
        return ResponseEntity.ok(ApiResponse.success(suggestions));
    }

    @GetMapping("/status/{status}")
    public ResponseEntity<ApiResponse<Page<Suggestion>>> getSuggestionsByStatus(
            @PathVariable String status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<Suggestion> suggestions = suggestionService.getSuggestionsByStatus(status, pageable);
        return ResponseEntity.ok(ApiResponse.success(suggestions));
    }

    @GetMapping("/my")
    public ResponseEntity<ApiResponse<List<Suggestion>>> getMySuggestions() {
        List<Suggestion> suggestions = suggestionService.getMySuggestions();
        return ResponseEntity.ok(ApiResponse.success(suggestions));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<Suggestion>> getSuggestion(@PathVariable Long id) {
        Suggestion suggestion = suggestionService.getSuggestion(id);
        return ResponseEntity.ok(ApiResponse.success(suggestion));
    }

    @PutMapping("/{id}/status")
    public ResponseEntity<ApiResponse<Suggestion>> updateStatus(
            @PathVariable Long id,
            @RequestParam String status,
            @RequestParam(required = false) String reply) {
        Suggestion suggestion = suggestionService.updateStatus(id, status, reply);
        return ResponseEntity.ok(ApiResponse.success("상태 변경 성공", suggestion));
    }
}
