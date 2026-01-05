package com.company.portal.repository;

import com.company.portal.entity.ApprovalLine;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ApprovalLineRepository extends JpaRepository<ApprovalLine, Long> {

    List<ApprovalLine> findByApprovalIdOrderByApprovalOrder(Long approvalId);

    Optional<ApprovalLine> findByApprovalIdAndApproverId(Long approvalId, Long approverId);
}
