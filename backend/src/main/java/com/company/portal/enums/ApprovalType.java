package com.company.portal.enums;

public enum ApprovalType {
    VACATION("휴가"),
    BUSINESS_TRIP("출장"),
    EXPENSE("지출결의"),
    OVERTIME("연장근무"),
    PURCHASE("구매요청"),
    OTHER("기타");

    private final String korean;

    ApprovalType(String korean) {
        this.korean = korean;
    }

    public String getKorean() {
        return korean;
    }
}
