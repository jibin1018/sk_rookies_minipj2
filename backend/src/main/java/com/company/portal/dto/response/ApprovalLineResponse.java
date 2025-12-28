package com.company.portal.dto.response;

import java.time.LocalDateTime;

import com.company.portal.enums.ApprovalStatus;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApprovalLineResponse {

    private Long id;
    private String approverName;
    private Long approverId;
    private Integer stepOrder;
    private ApprovalStatus status;
    private String comment;
    private LocalDateTime approvedAt;
}
