package com.company.portal.service.common;

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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
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

        // 결재 문서 생성
        Approval approval = Approval.builder()
                .documentType(request.getDocumentType())
                .title(request.getTitle())
                .content(request.getContent())
                .requester(requester)
                .currentStep(1)
                .status(ApprovalStatus.PENDING)
                .approvalLines(new ArrayList<>())
                .build();

        // 결재선 생성
        for (int i = 0; i < request.getApproverIds().size(); i++) {
            Long approverId = request.getApproverIds().get(i);
            Employee approver = employeeRepository.findById(approverId)
                    .orElseThrow(() -> new ResourceNotFoundException("결재자를 찾을 수 없습니다: " + approverId));

            ApprovalLine line = ApprovalLine.builder()
                    .approval(approval)
                    .approver(approver)
                    .stepOrder(i + 1)
                    .status(ApprovalStatus.PENDING)
                    .build();

            approval.getApprovalLines().add(line);
        }

        Approval savedApproval = approvalRepository.save(approval);

        log.info("결재 상신 성공: id={}, requester={}", savedApproval.getId(), currentEmployeeId);

        return convertToResponse(savedApproval);
    }

    @Transactional(readOnly = true)
    public Page<ApprovalResponse> getMyApprovals(Pageable pageable) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        return approvalRepository.findByRequesterId(currentEmployeeId, pageable)
                .map(this::convertToResponse);
    }

    @Transactional(readOnly = true)
    public Page<ApprovalResponse> getMyApprovalsByStatus(ApprovalStatus status, Pageable pageable) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        return approvalRepository.findByRequesterIdAndStatus(currentEmployeeId, status, pageable)
                .map(this::convertToResponse);
    }

    @Transactional(readOnly = true)
    public List<ApprovalResponse> getPendingApprovals() {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        log.info("결재 대기 조회 시작 - Employee ID: {}", currentEmployeeId);

        // 현재 사용자가 결재자로 등록되어 있고 PENDING 상태인 결재선 찾기
        List<ApprovalLine> pendingLines = approvalLineRepository.findByApproverIdAndStatus(
                currentEmployeeId,
                ApprovalStatus.PENDING
        );

        log.info("PENDING 상태 결재선 개수: {}", pendingLines.size());

        // 결재선에서 결재 문서 추출
        List<Approval> approvals = pendingLines.stream()
                .map(ApprovalLine::getApproval)
                .distinct()
                .collect(Collectors.toList());

        log.info("결재 대기 문서 개수: {}", approvals.size());

        return approvals.stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public ApprovalResponse getApproval(Long id) {
        Approval approval = approvalRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("결재 문서를 찾을 수 없습니다"));

        return convertToResponse(approval);
    }

    @Transactional
    public ApprovalResponse processApproval(Long id, ApprovalActionRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Approval approval = approvalRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("결재 문서를 찾을 수 없습니다"));

        // 현재 단계의 결재자 확인
        ApprovalLine currentLine = approval.getApprovalLines().stream()
                .filter(line -> line.getStepOrder().equals(approval.getCurrentStep()))
                .findFirst()
                .orElseThrow(() -> new BadRequestException("현재 결재 단계를 찾을 수 없습니다"));

        // 결재자 본인 확인
        if (!currentLine.getApprover().getId().equals(currentEmployeeId)) {
            throw new UnauthorizedException("결재할 권한이 없습니다");
        }

        // 이미 처리된 경우
        if (currentLine.getStatus() != ApprovalStatus.PENDING) {
            throw new BadRequestException("이미 처리된 결재입니다");
        }

        LocalDateTime now = LocalDateTime.now();

        if ("APPROVE".equals(request.getAction())) {
            // 승인
            currentLine.setStatus(ApprovalStatus.APPROVED);
            currentLine.setComment(request.getComment());
            currentLine.setApprovedAt(now);

            // 다음 단계로
            if (approval.getCurrentStep() < approval.getApprovalLines().size()) {
                approval.setCurrentStep(approval.getCurrentStep() + 1);
                approval.setStatus(ApprovalStatus.IN_PROGRESS);
            } else {
                // 최종 승인
                approval.setStatus(ApprovalStatus.APPROVED);
            }

            log.info("결재 승인: approval={}, step={}", id, currentLine.getStepOrder());

        } else if ("REJECT".equals(request.getAction())) {
            // 반려
            currentLine.setStatus(ApprovalStatus.REJECTED);
            currentLine.setComment(request.getComment());
            currentLine.setApprovedAt(now);

            approval.setStatus(ApprovalStatus.REJECTED);

            log.info("결재 반려: approval={}, step={}", id, currentLine.getStepOrder());
        } else {
            throw new BadRequestException("잘못된 액션입니다");
        }

        approvalLineRepository.save(currentLine);
        Approval updatedApproval = approvalRepository.save(approval);

        return convertToResponse(updatedApproval);
    }

    @Transactional
    public void cancelApproval(Long id) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Approval approval = approvalRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("결재 문서를 찾을 수 없습니다"));

        // 요청자 본인만 취소 가능
        if (!approval.getRequester().getId().equals(currentEmployeeId)) {
            throw new UnauthorizedException("취소할 권한이 없습니다");
        }

        // 이미 승인되거나 반려된 경우 취소 불가
        if (approval.getStatus() == ApprovalStatus.APPROVED
                || approval.getStatus() == ApprovalStatus.REJECTED) {
            throw new BadRequestException("승인되거나 반려된 결재는 취소할 수 없습니다");
        }

        approval.setStatus(ApprovalStatus.CANCELLED);
        approvalRepository.save(approval);

        log.info("결재 취소: approval={}", id);
    }

    private ApprovalResponse convertToResponse(Approval approval) {
        List<ApprovalLineResponse> lines = approval.getApprovalLines().stream()
                .map(line -> ApprovalLineResponse.builder()
                .id(line.getId())
                .approverName(line.getApprover().getName())
                .approverId(line.getApprover().getId())
                .stepOrder(line.getStepOrder())
                .status(line.getStatus())
                .comment(line.getComment())
                .approvedAt(line.getApprovedAt())
                .build())
                .collect(Collectors.toList());

        return ApprovalResponse.builder()
                .id(approval.getId())
                .documentType(approval.getDocumentType())
                .title(approval.getTitle())
                .content(approval.getContent())
                .requesterName(approval.getRequester().getName())
                .requesterId(approval.getRequester().getId())
                .currentStep(approval.getCurrentStep())
                .status(approval.getStatus())
                .approvalLines(lines)
                .createdAt(approval.getCreatedAt())
                .build();
    }
}
