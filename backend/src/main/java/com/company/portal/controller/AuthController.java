package com.company.portal.controller;

import com.company.portal.dto.request.LoginRequest;
import com.company.portal.dto.request.SignupRequest;
import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.LoginResponse;
import com.company.portal.service.secure.SecureAuthService;
import com.company.portal.service.vulnerable.VulnerableAuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final SecureAuthService secureAuthService;
    private final VulnerableAuthService vulnerableAuthService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");
        log.info("로그인 요청 - 보안 모드: {}", securityMode);

        LoginResponse response;

        if ("vulnerable".equals(securityMode)) {
            response = vulnerableAuthService.login(request);
        } else {
            response = secureAuthService.login(request);
        }

        return ResponseEntity.ok(ApiResponse.success("로그인 성공", response));
    }

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<Void>> signup(
            @Valid @RequestBody SignupRequest request,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");
        log.info("회원가입 요청 - 보안 모드: {}", securityMode);

        if ("vulnerable".equals(securityMode)) {
            vulnerableAuthService.signup(request);
        } else {
            secureAuthService.signup(request);
        }

        return ResponseEntity.ok(ApiResponse.success("회원가입 성공", null));
    }

    @GetMapping("/test")
    public ResponseEntity<ApiResponse<String>> test() {
        return ResponseEntity.ok(ApiResponse.success("API 연결 성공", "Hello from backend!"));
    }
}
