package com.company.portal.service.secure;

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
import com.company.portal.security.CustomUserDetails;
import com.company.portal.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecureAuthService {

    private final EmployeeRepository employeeRepository;
    private final DepartmentRepository departmentRepository;
    private final TeamRepository teamRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;

    @Transactional
    public LoginResponse login(LoginRequest request) {
        // Spring Security를 통한 인증
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmployeeId(),
                        request.getPassword()
                )
        );

        // JWT 토큰 생성
        String token = tokenProvider.generateToken(authentication);

        // 사용자 정보 조회
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        Employee employee = employeeRepository.findById(userDetails.getId())
                .orElseThrow(() -> new BadRequestException("사용자를 찾을 수 없습니다"));

        log.info("Secure 모드 - 로그인 성공: {}", employee.getEmployeeId());

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

        // 비밀번호 암호화 (Secure 모드)
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        // 사원 생성
        Employee employee = Employee.builder()
                .employeeId(request.getEmployeeId())
                .password(encodedPassword)
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
