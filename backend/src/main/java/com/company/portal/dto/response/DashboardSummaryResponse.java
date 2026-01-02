package com.company.portal.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DashboardSummaryResponse {

    // 통계 카드
    private Long boardCount;          // 사내 게시판 전체 글 수
    private Long weeklySchedule;      // 팀 일정 수 (이번 주)
    private Long pendingApproval;     // 내가 결재해야 할 문서 수
    private Long suggestionCount;     // 익명 건의함 전체 글 수

    // 최근 공지사항 리스트
    private List<RecentNotice> recentNotices;

    // 이번 주 일정 리스트
    private List<WeeklySchedule> weeklySchedules;

    // ===== 내부 클래스 =====
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RecentNotice {

        private Long id;
        private String title;
        private String authorName;
        private String createdAt;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class WeeklySchedule {

        private Long id;
        private String title;
        private String date;
        private String time;
    }
}
