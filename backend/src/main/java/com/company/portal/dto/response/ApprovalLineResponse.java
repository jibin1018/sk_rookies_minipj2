package com.company.portal.dto.response;

import com.company.portal.enums.ApprovalStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApprovalLineResponse {

    private Long id;
    private String approverName;
    private Long approverId;
    private String approverDepartment;
    private String approverPosition;
    private Integer approvalOrder;
    private ApprovalStatus status;
    private LocalDateTime approvedAt;
    private LocalDateTime rejectedAt;
    private String comment;
}
