package com.company.portal.controller;

import com.company.portal.dto.request.LoginRequest;
import com.company.portal.dto.request.SignupRequest;
import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.LoginResponse;
import com.company.portal.service.secure.SecureAuthService;
import com.company.portal.service.vulnerable.VulnerableAuthService;
import jakarta.servlet.http.HttpServletRequest;
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
            @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");
        log.info("로그인 요청 - 사번: {}, 보안모드: {}", request.getEmployeeId(), securityMode);

        try {
            LoginResponse response;

            if ("vulnerable".equalsIgnoreCase(securityMode)) {
                log.info("Vulnerable 모드로 로그인 시도");
                response = vulnerableAuthService.login(request);
            } else {
                log.info("Secure 모드로 로그인 시도");
                response = secureAuthService.login(request);
            }

            return ResponseEntity.ok(ApiResponse.success("로그인 성공", response));

        } catch (Exception e) {
            log.error("로그인 실패: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("아이디 또는 비밀번호가 올바르지 않습니다"));
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<Void>> signup(@RequestBody SignupRequest request) {
        // 회원가입 기능은 미구현
        return ResponseEntity.ok(ApiResponse.success("회원가입 기능은 준비중입니다", null));
    }

    @GetMapping("/test")
    public ResponseEntity<ApiResponse<String>> test() {
        return ResponseEntity.ok(ApiResponse.success("성공", "Hello from backend!"));
    }
}
