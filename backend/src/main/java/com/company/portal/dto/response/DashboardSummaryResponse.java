package com.company.portal.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DashboardSummaryResponse {

    private Long totalEmployees;
    private Long presentToday;
    private Long absentToday;
    private Long lateToday;
    private Long pendingApprovals;
    private Long unreadNotices;
}
