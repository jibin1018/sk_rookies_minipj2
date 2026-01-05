package com.company.portal.enums;

public enum BoardCategory {
    NOTICE("공지사항"),
    FREE("자유게시판"),
    EVENT("경조사"),
    CLUB("동호회"),
    MARKET("중고거래");

    private final String korean;

    BoardCategory(String korean) {
        this.korean = korean;
    }

    public String getKorean() {
        return korean;
    }
}
