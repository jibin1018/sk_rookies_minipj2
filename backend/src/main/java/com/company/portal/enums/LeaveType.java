package com.company.portal.enums;

public enum LeaveType {
    ANNUAL("연차"),
    HALF_DAY("반차"),
    SICK("병가"),
    FAMILY_EVENT("경조휴가");

    private final String korean;

    LeaveType(String korean) {
        this.korean = korean;
    }

    public String getKorean() {
        return korean;
    }
}
