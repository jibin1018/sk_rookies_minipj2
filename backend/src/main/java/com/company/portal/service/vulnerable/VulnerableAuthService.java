package com.company.portal.service.vulnerable;

import com.company.portal.dto.request.LoginRequest;
import com.company.portal.dto.request.SignupRequest;
import com.company.portal.dto.response.LoginResponse;
import com.company.portal.entity.Employee;
import com.company.portal.exception.BadRequestException;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.security.JwtTokenProvider;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.Query;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@Slf4j
@Service
@RequiredArgsConstructor
public class VulnerableAuthService {

    private final EmployeeRepository employeeRepository;
    private final EntityManager entityManager;
    private final JwtTokenProvider tokenProvider;

    @Transactional
    public LoginResponse login(LoginRequest request) {
        log.info("Vulnerable 모드 - 로그인 시도: {}", request.getEmployeeId());

        // SQL Injection 취약점 (문자열 연결)
        String sql = "SELECT * FROM employees WHERE employee_id = '" + request.getEmployeeId()
                + "' AND password = '" + request.getPassword() + "'";

        log.info("실행 SQL: {}", sql);

        Query query = entityManager.createNativeQuery(sql, Employee.class);

        try {
            Employee employee = (Employee) query.getSingleResult();

            log.info("Vulnerable 모드 - 로그인 성공: {}", employee.getEmployeeId());

            // 토큰 생성
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    employee.getEmployeeId(),
                    employee.getPassword(),
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + employee.getRole().name()))
            );
            String token = tokenProvider.generateToken(authentication);

            return LoginResponse.builder()
                    .token(token)
                    .id(employee.getId())
                    .employeeId(employee.getEmployeeId())
                    .name(employee.getName())
                    .email(employee.getEmail())
                    .departmentId(employee.getDepartment() != null ? employee.getDepartment().getId() : null)
                    .departmentName(employee.getDepartment() != null ? employee.getDepartment().getName() : null)
                    .teamId(employee.getTeam() != null ? employee.getTeam().getId() : null)
                    .teamName(employee.getTeam() != null ? employee.getTeam().getName() : null)
                    .position(employee.getPosition())
                    .role(employee.getRole())
                    .build();

        } catch (NoResultException e) {
            log.error("Vulnerable 모드 - 사용자를 찾을 수 없음");
            throw new BadRequestException("아이디 또는 비밀번호가 올바르지 않습니다");
        }
    }

    @Transactional
    public void signup(SignupRequest request) {
        // 평문 비밀번호 저장 (취약점)
        log.warn("Vulnerable 모드 - 비밀번호 평문 저장");

        if (employeeRepository.existsByEmployeeId(request.getEmployeeId())) {
            throw new BadRequestException("이미 존재하는 사번입니다");
        }

        Employee employee = Employee.builder()
                .employeeId(request.getEmployeeId())
                .password(request.getPassword()) // 평문 저장
                .name(request.getName())
                .email(request.getEmail())
                .position(request.getPosition())
                .role(request.getRole())
                .hireDate(request.getHireDate())
                .isActive(true)
                .build();

        employeeRepository.save(employee);
        log.info("Vulnerable 모드 - 회원가입 완료: {}", employee.getEmployeeId());
    }
}
