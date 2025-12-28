package com.company.portal.service.vulnerable;

import com.company.portal.dto.request.LoginRequest;
import com.company.portal.dto.request.SignupRequest;
import com.company.portal.dto.response.LoginResponse;
import com.company.portal.entity.Department;
import com.company.portal.entity.Employee;
import com.company.portal.entity.SecurityLog;
import com.company.portal.entity.Team;
import com.company.portal.enums.Role;
import com.company.portal.exception.BadRequestException;
import com.company.portal.repository.DepartmentRepository;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.repository.SecurityLogRepository;
import com.company.portal.repository.TeamRepository;
import com.company.portal.security.JwtTokenProvider;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class VulnerableAuthService {

    private final EmployeeRepository employeeRepository;
    private final DepartmentRepository departmentRepository;
    private final TeamRepository teamRepository;
    private final SecurityLogRepository securityLogRepository;
    private final JwtTokenProvider tokenProvider;
    private final EntityManager entityManager;

    @Transactional
    public LoginResponse login(LoginRequest request) {
        // SQL Injection 취약점 - 문자열 연결 사용
        String sql = "SELECT e FROM Employee e WHERE e.employeeId = '"
                + request.getEmployeeId() + "' AND e.password = '"
                + request.getPassword() + "'";

        log.warn("Vulnerable 모드 - SQL Injection 가능: {}", sql);

        try {
            Query query = entityManager.createQuery(sql);
            @SuppressWarnings("unchecked")
            List<Employee> results = query.getResultList();

            if (results.isEmpty()) {
                // 보안 로그 기록
                logSecurityEvent("SQL_INJECTION_ATTEMPT",
                        "Login attempt with potentially malicious input: " + request.getEmployeeId());

                throw new BadRequestException("아이디 또는 비밀번호가 올바르지 않습니다");
            }

            Employee employee = results.get(0);

            // SQL Injection 성공 로그
            if (request.getEmployeeId().contains("'") || request.getEmployeeId().contains("--")) {
                logSecurityEvent("SQL_INJECTION_SUCCESS",
                        "SQL Injection successful! Input: " + request.getEmployeeId());
            }

            // JWT 토큰 생성
            UsernamePasswordAuthenticationToken authentication
                    = new UsernamePasswordAuthenticationToken(
                            employee.getEmployeeId(),
                            null,
                            Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + employee.getRole()))
                    );

            String token = tokenProvider.generateToken(authentication);

            log.warn("Vulnerable 모드 - 로그인 성공 (취약점 노출): {}", employee.getEmployeeId());

            return LoginResponse.builder()
                    .token(token)
                    .id(employee.getId())
                    .employeeId(employee.getEmployeeId())
                    .name(employee.getName())
                    .email(employee.getEmail())
                    .departmentName(employee.getDepartment() != null ? employee.getDepartment().getName() : null)
                    .teamName(employee.getTeam() != null ? employee.getTeam().getName() : null)
                    .position(employee.getPosition())
                    .role(employee.getRole())
                    .build();

        } catch (Exception e) {
            log.error("Vulnerable 모드 - 로그인 오류: ", e);
            throw new BadRequestException("로그인 실패: " + e.getMessage());
        }
    }

    @Transactional
    public void signup(SignupRequest request) {
        // 중복 체크
        if (employeeRepository.existsByEmployeeId(request.getEmployeeId())) {
            throw new BadRequestException("이미 존재하는 사번입니다");
        }

        if (employeeRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("이미 존재하는 이메일입니다");
        }

        // 부서 조회
        Department department = departmentRepository.findById(request.getDepartmentId())
                .orElseThrow(() -> new BadRequestException("부서를 찾을 수 없습니다"));

        // 팀 조회
        Team team = null;
        if (request.getTeamId() != null) {
            team = teamRepository.findById(request.getTeamId())
                    .orElseThrow(() -> new BadRequestException("팀을 찾을 수 없습니다"));
        }

        // 비밀번호 평문 저장 (Vulnerable 모드 - 심각한 취약점!)
        String plainPassword = request.getPassword();

        log.warn("Vulnerable 모드 - 비밀번호 평문 저장 (심각한 취약점!): {}", request.getEmployeeId());

        // 사원 생성
        Employee employee = Employee.builder()
                .employeeId(request.getEmployeeId())
                .password(plainPassword) // 평문 저장!
                .name(request.getName())
                .email(request.getEmail())
                .department(department)
                .team(team)
                .position(request.getPosition())
                .role(request.getRole() != null ? request.getRole() : Role.USER)
                .hireDate(request.getHireDate())
                .phone(request.getPhone())
                .isActive(true)
                .build();

        employeeRepository.save(employee);

        // 보안 로그 기록
        logSecurityEvent("PLAIN_PASSWORD_STORAGE",
                "Password stored in plain text for employee: " + employee.getEmployeeId());

        log.warn("Vulnerable 모드 - 회원가입 성공 (비밀번호 평문 저장): {}", employee.getEmployeeId());
    }

    private void logSecurityEvent(String attackType, String details) {
        SecurityLog securityLog = SecurityLog.builder()
                .attackType(attackType)
                .securityMode("vulnerable")
                .details(details)
                .build();

        securityLogRepository.save(securityLog);
    }
}
