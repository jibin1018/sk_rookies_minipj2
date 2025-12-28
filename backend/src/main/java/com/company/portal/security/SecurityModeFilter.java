package com.company.portal.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class SecurityModeFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        // X-Security-Mode 헤더 읽기 (vulnerable 또는 secure)
        String securityMode = httpRequest.getHeader("X-Security-Mode");

        if (securityMode == null || securityMode.isEmpty()) {
            securityMode = "secure";  // 기본값은 secure
        }

        // Request Attribute에 저장하여 Service에서 사용
        request.setAttribute("securityMode", securityMode);

        log.debug("Security Mode: {}", securityMode);

        chain.doFilter(request, response);
    }
}
