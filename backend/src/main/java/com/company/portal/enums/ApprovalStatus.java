package com.company.portal.enums;

public enum ApprovalStatus {
    PENDING("대기"),
    APPROVED("승인"),
    REJECTED("반려"),
    CANCELLED("취소");

    private final String korean;

    ApprovalStatus(String korean) {
        this.korean = korean;
    }

    public String getKorean() {
        return korean;
    }
}
