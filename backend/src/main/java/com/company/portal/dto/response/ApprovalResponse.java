package com.company.portal.dto.response;

import com.company.portal.enums.ApprovalStatus;
import com.company.portal.enums.ApprovalType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApprovalResponse {

    private Long id;
    private ApprovalType type;
    private String title;
    private String content;
    private String requesterName;
    private Long requesterId;
    private String requesterDepartment;
    private String requesterPosition;
    private ApprovalStatus status;
    private LocalDateTime approvedAt;
    private LocalDateTime rejectedAt;
    private String rejectReason;
    private List<ApprovalLineResponse> approvalLines;
    private LocalDateTime createdAt;
}
