package com.company.portal.controller;

import com.company.portal.dto.request.ApprovalActionRequest;
import com.company.portal.dto.request.ApprovalRequest;
import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.ApprovalResponse;
import com.company.portal.service.ApprovalService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/approvals")
@RequiredArgsConstructor
public class ApprovalController {

    private final ApprovalService approvalService;

    @PostMapping
    public ResponseEntity<ApiResponse<ApprovalResponse>> createApproval(@Valid @RequestBody ApprovalRequest request) {
        ApprovalResponse response = approvalService.createApproval(request);
        return ResponseEntity.ok(ApiResponse.success("결재 요청 성공", response));
    }

    @GetMapping("/my")
    public ResponseEntity<ApiResponse<List<ApprovalResponse>>> getMyApprovals() {
        List<ApprovalResponse> response = approvalService.getMyApprovals();
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/pending")
    public ResponseEntity<ApiResponse<List<ApprovalResponse>>> getPendingApprovals() {
        List<ApprovalResponse> response = approvalService.getPendingApprovals();
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/completed")
    public ResponseEntity<ApiResponse<List<ApprovalResponse>>> getCompletedApprovals() {
        List<ApprovalResponse> response = approvalService.getCompletedApprovals();
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<ApprovalResponse>> getApproval(@PathVariable Long id) {
        ApprovalResponse response = approvalService.getApproval(id);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/{id}/approve")
    public ResponseEntity<ApiResponse<ApprovalResponse>> approveApproval(
            @PathVariable Long id,
            @RequestBody ApprovalActionRequest request) {
        ApprovalResponse response = approvalService.approveApproval(id, request);
        return ResponseEntity.ok(ApiResponse.success("결재 승인 완료", response));
    }

    @PostMapping("/{id}/reject")
    public ResponseEntity<ApiResponse<ApprovalResponse>> rejectApproval(
            @PathVariable Long id,
            @RequestBody ApprovalActionRequest request) {
        ApprovalResponse response = approvalService.rejectApproval(id, request);
        return ResponseEntity.ok(ApiResponse.success("결재 반려 완료", response));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> cancelApproval(@PathVariable Long id) {
        approvalService.cancelApproval(id);
        return ResponseEntity.ok(ApiResponse.success("결재 취소 완료", null));
    }
}
