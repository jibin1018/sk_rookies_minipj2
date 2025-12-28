package com.company.portal.controller;

import com.company.portal.dto.request.ApprovalActionRequest;
import com.company.portal.dto.request.ApprovalRequest;
import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.ApprovalResponse;
import com.company.portal.enums.ApprovalStatus;
import com.company.portal.service.common.ApprovalService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/approvals")
@RequiredArgsConstructor
public class ApprovalController {

    private final ApprovalService approvalService;

    @PostMapping
    public ResponseEntity<ApiResponse<ApprovalResponse>> createApproval(
            @Valid @RequestBody ApprovalRequest request) {
        ApprovalResponse response = approvalService.createApproval(request);
        return ResponseEntity.ok(ApiResponse.success("결재 상신 성공", response));
    }

    @GetMapping("/my")
    public ResponseEntity<ApiResponse<Page<ApprovalResponse>>> getMyApprovals(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<ApprovalResponse> response = approvalService.getMyApprovals(pageable);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/my/status/{status}")
    public ResponseEntity<ApiResponse<Page<ApprovalResponse>>> getMyApprovalsByStatus(
            @PathVariable ApprovalStatus status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<ApprovalResponse> response = approvalService.getMyApprovalsByStatus(status, pageable);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/pending")
    public ResponseEntity<ApiResponse<List<ApprovalResponse>>> getPendingApprovals() {
        List<ApprovalResponse> response = approvalService.getPendingApprovals();
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<ApprovalResponse>> getApproval(@PathVariable Long id) {
        ApprovalResponse response = approvalService.getApproval(id);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/{id}/process")
    public ResponseEntity<ApiResponse<ApprovalResponse>> processApproval(
            @PathVariable Long id,
            @Valid @RequestBody ApprovalActionRequest request) {
        ApprovalResponse response = approvalService.processApproval(id, request);
        return ResponseEntity.ok(ApiResponse.success("결재 처리 성공", response));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> cancelApproval(@PathVariable Long id) {
        approvalService.cancelApproval(id);
        return ResponseEntity.ok(ApiResponse.success("결재 취소 성공", null));
    }
}
