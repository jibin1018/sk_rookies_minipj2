package com.company.portal.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.company.portal.entity.ApprovalLine;
import com.company.portal.enums.ApprovalStatus;

@Repository
public interface ApprovalLineRepository extends JpaRepository<ApprovalLine, Long> {

    List<ApprovalLine> findByApprovalIdOrderByStepOrderAsc(Long approvalId);

    List<ApprovalLine> findByApproverIdAndStatus(Long approverId, ApprovalStatus status);

    @Query("SELECT al FROM ApprovalLine al WHERE al.approver.id = :approverId AND al.approval.status = :approvalStatus")
    List<ApprovalLine> findPendingApprovalsByApproverId(
            @Param("approverId") Long approverId,
            @Param("approvalStatus") ApprovalStatus approvalStatus
    );
}
