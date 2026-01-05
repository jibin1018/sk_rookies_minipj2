package com.company.portal.repository;

import com.company.portal.entity.LeaveRequest;
import com.company.portal.enums.ApprovalStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface LeaveRequestRepository extends JpaRepository<LeaveRequest, Long> {

    List<LeaveRequest> findByEmployeeId(Long employeeId);

    List<LeaveRequest> findByEmployeeIdAndStatus(Long employeeId, ApprovalStatus status);

    List<LeaveRequest> findByApproverId(Long approverId);

    List<LeaveRequest> findByApproverIdAndStatus(Long approverId, ApprovalStatus status);
}
