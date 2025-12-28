package com.company.portal.dto.response;

import java.time.LocalDateTime;
import java.util.List;

import com.company.portal.enums.ApprovalStatus;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApprovalResponse {

    private Long id;
    private String documentType;
    private String title;
    private String content;
    private String requesterName;
    private Long requesterId;
    private Integer currentStep;
    private ApprovalStatus status;
    private List<ApprovalLineResponse> approvalLines;
    private LocalDateTime createdAt;
}
