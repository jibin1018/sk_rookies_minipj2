package com.company.portal.util;

import org.apache.commons.text.StringEscapeUtils;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class ValidationUtil {

    private static final Pattern SQL_INJECTION_PATTERN
            = Pattern.compile("('.+--)|(--)|(\\|\\|)|(/\\*(?:.|[\\n\\r])*?\\*/)", Pattern.CASE_INSENSITIVE);

    private static final Pattern XSS_PATTERN
            = Pattern.compile("<script|javascript:|onerror=|onload=", Pattern.CASE_INSENSITIVE);

    // Secure 모드: HTML 이스케이프
    public String escapeHtml(String input) {
        if (input == null) {
            return null;
        }
        return StringEscapeUtils.escapeHtml4(input);
    }

    // Secure 모드: XSS 검증
    public boolean containsXss(String input) {
        if (input == null) {
            return false;
        }
        return XSS_PATTERN.matcher(input).find();
    }

    // Secure 모드: SQL Injection 검증
    public boolean containsSqlInjection(String input) {
        if (input == null) {
            return false;
        }
        return SQL_INJECTION_PATTERN.matcher(input).find();
    }

    // Secure 모드: 입력값 검증 및 정제
    public String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }

        // XSS 방지
        String sanitized = escapeHtml(input);

        // 추가 정제 (필요시)
        sanitized = sanitized.trim();

        return sanitized;
    }
}
