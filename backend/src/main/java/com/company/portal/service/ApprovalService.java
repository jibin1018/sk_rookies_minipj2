package com.company.portal.service;

import com.company.portal.dto.request.ApprovalActionRequest;
import com.company.portal.dto.request.ApprovalRequest;
import com.company.portal.dto.response.ApprovalLineResponse;
import com.company.portal.dto.response.ApprovalResponse;
import com.company.portal.entity.Approval;
import com.company.portal.entity.ApprovalLine;
import com.company.portal.entity.Employee;
import com.company.portal.enums.ApprovalStatus;
import com.company.portal.exception.BadRequestException;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.exception.UnauthorizedException;
import com.company.portal.repository.ApprovalLineRepository;
import com.company.portal.repository.ApprovalRepository;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ApprovalService {

    private final ApprovalRepository approvalRepository;
    private final ApprovalLineRepository approvalLineRepository;
    private final EmployeeRepository employeeRepository;

    @Transactional
    public ApprovalResponse createApproval(ApprovalRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        Employee requester = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        Approval approval = Approval.builder()
                .type(request.getType())
                .title(request.getTitle())
                .content(request.getContent())
                .requester(requester)
                .status(ApprovalStatus.PENDING)
                .build();

        Approval savedApproval = approvalRepository.save(approval);

        List<ApprovalLine> approvalLines = new ArrayList<>();
        for (int i = 0; i < request.getApproverIds().size(); i++) {
            Long approverId = request.getApproverIds().get(i);
            Employee approver = employeeRepository.findById(approverId)
                    .orElseThrow(() -> new ResourceNotFoundException("결재자를 찾을 수 없습니다: " + approverId));

            ApprovalLine line = ApprovalLine.builder()
                    .approval(savedApproval)
                    .approver(approver)
                    .approvalOrder(i + 1)
                    .status(ApprovalStatus.PENDING)
                    .build();

            approvalLines.add(line);
        }

        approvalLineRepository.saveAll(approvalLines);
        savedApproval.setApprovalLines(approvalLines);

        log.info("결재 생성: {}", savedApproval.getId());

        return convertToResponse(savedApproval);
    }

    @Transactional(readOnly = true)
    public List<ApprovalResponse> getMyApprovals() {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        List<Approval> approvals = approvalRepository.findByRequesterIdOrderByCreatedAtDesc(currentEmployeeId);
        return approvals.stream().map(this::convertToResponse).collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<ApprovalResponse> getPendingApprovals() {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        List<Approval> approvals = approvalRepository.findPendingApprovalsByApproverId(currentEmployeeId);
        return approvals.stream().map(this::convertToResponse).collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<ApprovalResponse> getCompletedApprovals() {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        List<Approval> approvals = approvalRepository.findCompletedApprovalsByApproverId(currentEmployeeId);
        return approvals.stream().map(this::convertToResponse).collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public ApprovalResponse getApproval(Long id) {
        Approval approval = approvalRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("결재를 찾을 수 없습니다"));
        return convertToResponse(approval);
    }

    @Transactional
    public ApprovalResponse approveApproval(Long id, ApprovalActionRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Approval approval = approvalRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("결재를 찾을 수 없습니다"));

        ApprovalLine myLine = approvalLineRepository.findByApprovalIdAndApproverId(id, currentEmployeeId)
                .orElseThrow(() -> new UnauthorizedException("결재 권한이 없습니다"));

        if (myLine.getStatus() != ApprovalStatus.PENDING) {
            throw new BadRequestException("이미 처리된 결재입니다");
        }

        List<ApprovalLine> lines = approvalLineRepository.findByApprovalIdOrderByApprovalOrder(id);
        for (ApprovalLine line : lines) {
            if (line.getApprovalOrder() < myLine.getApprovalOrder()) {
                if (line.getStatus() != ApprovalStatus.APPROVED) {
                    throw new BadRequestException("이전 결재자의 승인이 필요합니다");
                }
            }
        }

        myLine.setStatus(ApprovalStatus.APPROVED);
        myLine.setApprovedAt(LocalDateTime.now());
        myLine.setComment(request.getComment());
        approvalLineRepository.save(myLine);

        boolean allApproved = lines.stream().allMatch(line -> line.getStatus() == ApprovalStatus.APPROVED);

        if (allApproved) {
            approval.setStatus(ApprovalStatus.APPROVED);
            approval.setApprovedAt(LocalDateTime.now());
            approvalRepository.save(approval);
        }

        log.info("결재 승인: {}", id);

        return convertToResponse(approval);
    }

    @Transactional
    public ApprovalResponse rejectApproval(Long id, ApprovalActionRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Approval approval = approvalRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("결재를 찾을 수 없습니다"));

        ApprovalLine myLine = approvalLineRepository.findByApprovalIdAndApproverId(id, currentEmployeeId)
                .orElseThrow(() -> new UnauthorizedException("결재 권한이 없습니다"));

        if (myLine.getStatus() != ApprovalStatus.PENDING) {
            throw new BadRequestException("이미 처리된 결재입니다");
        }

        myLine.setStatus(ApprovalStatus.REJECTED);
        myLine.setRejectedAt(LocalDateTime.now());
        myLine.setComment(request.getComment());
        approvalLineRepository.save(myLine);

        approval.setStatus(ApprovalStatus.REJECTED);
        approval.setRejectedAt(LocalDateTime.now());
        approval.setRejectReason(request.getRejectReason());
        approvalRepository.save(approval);

        log.info("결재 반려: {}", id);

        return convertToResponse(approval);
    }

    @Transactional
    public void cancelApproval(Long id) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Approval approval = approvalRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("결재를 찾을 수 없습니다"));

        if (!approval.getRequester().getId().equals(currentEmployeeId)) {
            throw new UnauthorizedException("결재를 취소할 권한이 없습니다");
        }

        if (approval.getStatus() != ApprovalStatus.PENDING) {
            throw new BadRequestException("대기 중인 결재만 취소할 수 있습니다");
        }

        approval.setStatus(ApprovalStatus.CANCELLED);
        approvalRepository.save(approval);

        log.info("결재 취소: {}", id);
    }

    private ApprovalResponse convertToResponse(Approval approval) {
        List<ApprovalLineResponse> lines = approval.getApprovalLines().stream()
                .sorted((a, b) -> a.getApprovalOrder().compareTo(b.getApprovalOrder()))
                .map(line -> ApprovalLineResponse.builder()
                .id(line.getId())
                .approverName(line.getApprover().getName())
                .approverId(line.getApprover().getId())
                .approverDepartment(line.getApprover().getDepartment() != null
                        ? line.getApprover().getDepartment().getName() : null)
                .approverPosition(line.getApprover().getPosition() != null
                        ? line.getApprover().getPosition().getKorean() : null)
                .approvalOrder(line.getApprovalOrder())
                .status(line.getStatus())
                .approvedAt(line.getApprovedAt())
                .rejectedAt(line.getRejectedAt())
                .comment(line.getComment())
                .build())
                .collect(Collectors.toList());

        return ApprovalResponse.builder()
                .id(approval.getId())
                .type(approval.getType())
                .title(approval.getTitle())
                .content(approval.getContent())
                .requesterName(approval.getRequester().getName())
                .requesterId(approval.getRequester().getId())
                .requesterDepartment(approval.getRequester().getDepartment() != null
                        ? approval.getRequester().getDepartment().getName() : null)
                .requesterPosition(approval.getRequester().getPosition() != null
                        ? approval.getRequester().getPosition().getKorean() : null)
                .status(approval.getStatus())
                .approvedAt(approval.getApprovedAt())
                .rejectedAt(approval.getRejectedAt())
                .rejectReason(approval.getRejectReason())
                .approvalLines(lines)
                .createdAt(approval.getCreatedAt())
                .build();
    }
}
