package com.company.portal.dto.response;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DashboardSummaryResponse {

    private long boardCount;        // 사내 게시판 새 글
    private long weeklySchedule;    // 이번 주 일정
    private long pendingApproval;   // 결재 대기
    private long suggestionCount;   // 진행중 건의사항
}
