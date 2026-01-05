package com.company.portal.repository;

import com.company.portal.entity.Approval;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ApprovalRepository extends JpaRepository<Approval, Long> {

    // 내가 요청한 결재 목록
    List<Approval> findByRequesterIdOrderByCreatedAtDesc(Long requesterId);

    // 내가 결재해야 할 목록
    @Query("SELECT DISTINCT a FROM Approval a "
            + "JOIN a.approvalLines al "
            + "WHERE al.approver.id = :approverId "
            + "AND al.status = 'PENDING' "
            + "AND a.status = 'PENDING' "
            + "ORDER BY a.createdAt DESC")
    List<Approval> findPendingApprovalsByApproverId(@Param("approverId") Long approverId);

    // 내가 결재한 목록
    @Query("SELECT DISTINCT a FROM Approval a "
            + "JOIN a.approvalLines al "
            + "WHERE al.approver.id = :approverId "
            + "AND al.status IN ('APPROVED', 'REJECTED') "
            + "ORDER BY a.createdAt DESC")
    List<Approval> findCompletedApprovalsByApproverId(@Param("approverId") Long approverId);

    // 전체 결재 목록
    List<Approval> findAllByOrderByCreatedAtDesc();

    // 대기 중인 결재 개수
    @Query("SELECT COUNT(DISTINCT a) FROM Approval a "
            + "JOIN a.approvalLines al "
            + "WHERE al.approver.id = :approverId "
            + "AND al.status = 'PENDING' "
            + "AND a.status = 'PENDING'")
    long countPendingByApprover(@Param("approverId") Long approverId);
}
