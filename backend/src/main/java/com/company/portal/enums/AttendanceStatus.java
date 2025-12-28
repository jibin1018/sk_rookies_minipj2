package com.company.portal.enums;

public enum AttendanceStatus {
    PRESENT("정상 출근"),
    LATE("지각"),
    EARLY_LEAVE("조퇴"),
    ABSENT("결근"),
    VACATION("휴가"),
    HALF_VACATION("반차"),
    SICK_LEAVE("병가"),
    BUSINESS_TRIP("출장");

    private final String korean;

    AttendanceStatus(String korean) {
        this.korean = korean;
    }

    public String getKorean() {
        return korean;
    }
}
