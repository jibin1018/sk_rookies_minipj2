package com.company.portal.service;

import com.company.portal.dto.request.LoginRequest;
import com.company.portal.dto.request.SignupRequest;
import com.company.portal.dto.response.LoginResponse;
import com.company.portal.entity.Department;
import com.company.portal.entity.Employee;
import com.company.portal.entity.Team;
import com.company.portal.enums.Role;
import com.company.portal.exception.BadRequestException;
import com.company.portal.repository.DepartmentRepository;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.repository.TeamRepository;
import com.company.portal.security.JwtTokenProvider;
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
public class AuthService {

    private final EmployeeRepository employeeRepository;
    private final DepartmentRepository departmentRepository;
    private final TeamRepository teamRepository;
    private final JwtTokenProvider tokenProvider;

    @Transactional
    public LoginResponse login(LoginRequest request) {
        log.info("Secure 모드 - 로그인 시도: {}", request.getEmployeeId());
        log.info("받은 비밀번호 (SHA-256 해시): {}", request.getPassword());

        // 사용자 조회
        Employee employee = employeeRepository.findByEmployeeId(request.getEmployeeId())
                .orElseThrow(() -> new BadRequestException("아이디 또는 비밀번호가 올바르지 않습니다"));

        // SHA-256 해시 비교
        String hashedPassword = request.getPassword();
        String storedPassword = employee.getPassword();

        log.info("DB 저장 비밀번호: {}", storedPassword);

        if (!storedPassword.equals(hashedPassword)) {
            log.error("비밀번호 불일치");
            throw new BadRequestException("아이디 또는 비밀번호가 올바르지 않습니다");
        }

        log.info("Secure 모드 - 로그인 성공: {}", employee.getEmployeeId());

        // JWT 토큰 생성
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

        // 팀 조회 (선택사항)
        Team team = null;
        if (request.getTeamId() != null) {
            team = teamRepository.findById(request.getTeamId())
                    .orElseThrow(() -> new BadRequestException("팀을 찾을 수 없습니다"));
        }

        // SHA-256 해시된 비밀번호 저장 (클라이언트에서 이미 해시됨)
        String hashedPassword = request.getPassword();

        log.info("Secure 모드 - 회원가입: SHA-256 해시 저장");

        // 사원 생성
        Employee employee = Employee.builder()
                .employeeId(request.getEmployeeId())
                .password(hashedPassword) // SHA-256 해시 저장
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

        log.info("Secure 모드 - 회원가입 성공: {}", employee.getEmployeeId());
    }
}
