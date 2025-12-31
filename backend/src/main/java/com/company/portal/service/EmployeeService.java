package com.company.portal.service;

import com.company.portal.dto.request.EmployeeCreateRequest;
import com.company.portal.dto.request.EmployeeUpdateRequest;
import com.company.portal.dto.response.EmployeeResponse;
import com.company.portal.entity.Department;
import com.company.portal.entity.Employee;
import com.company.portal.entity.Team;
import com.company.portal.enums.Position;
import com.company.portal.enums.Role;
import com.company.portal.exception.BadRequestException;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.repository.DepartmentRepository;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.repository.TeamRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmployeeService {

    private final EmployeeRepository employeeRepository;
    private final DepartmentRepository departmentRepository;
    private final TeamRepository teamRepository;

    /* =========================
       조회
    ========================== */
    @Transactional(readOnly = true)
    public List<EmployeeResponse> getAllEmployees() {
        return employeeRepository.findAll().stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public EmployeeResponse getEmployee(Long id) {
        Employee employee = employeeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("사원을 찾을 수 없습니다"));
        return toResponse(employee);
    }

    /* =========================
       생성
    ========================== */
    @Transactional
    public EmployeeResponse createEmployee(EmployeeCreateRequest request) {

        if (employeeRepository.existsByEmployeeId(request.getEmployeeId())) {
            throw new BadRequestException("이미 존재하는 사번입니다");
        }

        if (employeeRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("이미 존재하는 이메일입니다");
        }

        Department department = departmentRepository.findById(request.getDepartmentId())
                .orElseThrow(() -> new BadRequestException("부서를 찾을 수 없습니다"));

        Team team = null;
        if (request.getTeamId() != null) {
            team = teamRepository.findById(request.getTeamId())
                    .orElseThrow(() -> new BadRequestException("팀을 찾을 수 없습니다"));
        }

        Employee employee = Employee.builder()
                .employeeId(request.getEmployeeId())
                .password(request.getPassword()) // 이미 해시된 값
                .name(request.getName())
                .email(request.getEmail())
                .department(department)
                .team(team)
                .position(Position.valueOf(request.getPosition().toUpperCase()))
                .role(request.getRole() != null ? request.getRole() : Role.USER)
                .hireDate(request.getHireDate())
                .phone(request.getPhone())
                .isActive(true)
                .build();

        Employee saved = employeeRepository.save(employee);
        log.info("사원 생성 성공: {}", saved.getEmployeeId());

        return toResponse(saved);
    }

    /* =========================
       수정
    ========================== */
    @Transactional
    public EmployeeResponse updateEmployee(Long id, EmployeeUpdateRequest request) {

        Employee employee = employeeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("사원을 찾을 수 없습니다"));

        if (request.getEmail() != null && !request.getEmail().equals(employee.getEmail())) {
            if (employeeRepository.existsByEmail(request.getEmail())) {
                throw new BadRequestException("이미 존재하는 이메일입니다");
            }
            employee.setEmail(request.getEmail());
        }

        if (request.getDepartmentId() != null) {
            Department department = departmentRepository.findById(request.getDepartmentId())
                    .orElseThrow(() -> new BadRequestException("부서를 찾을 수 없습니다"));
            employee.setDepartment(department);
        }

        if (request.getTeamId() != null) {
            Team team = teamRepository.findById(request.getTeamId())
                    .orElseThrow(() -> new BadRequestException("팀을 찾을 수 없습니다"));
            employee.setTeam(team);
        }

        if (request.getName() != null) {
            employee.setName(request.getName());
        }
        if (request.getPosition() != null) {
            employee.setPosition(Position.valueOf(request.getPosition().toUpperCase()));
        }
        if (request.getRole() != null) {
            employee.setRole(request.getRole());
        }
        if (request.getHireDate() != null) {
            employee.setHireDate(request.getHireDate());
        }
        if (request.getPhone() != null) {
            employee.setPhone(request.getPhone());
        }
        if (request.getIsActive() != null) {
            employee.setIsActive(request.getIsActive());
        }

        Employee updated = employeeRepository.save(employee);
        log.info("사원 정보 수정 성공: {}", updated.getEmployeeId());

        return toResponse(updated);
    }

    /* =========================
       삭제
    ========================== */
    @Transactional
    public void deleteEmployee(Long id) {
        Employee employee = employeeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("사원을 찾을 수 없습니다"));

        employeeRepository.delete(employee);
        log.info("사원 삭제 성공: {}", employee.getEmployeeId());
    }

    /* =========================
       Entity → DTO 변환
    ========================== */
    private EmployeeResponse toResponse(Employee employee) {
        return EmployeeResponse.builder()
                .id(employee.getId())
                .employeeId(employee.getEmployeeId())
                .name(employee.getName())
                .email(employee.getEmail())
                .departmentId(
                        employee.getDepartment() != null ? employee.getDepartment().getId() : null
                )
                .departmentName(
                        employee.getDepartment() != null ? employee.getDepartment().getName() : null
                )
                .teamId(
                        employee.getTeam() != null ? employee.getTeam().getId() : null
                )
                .teamName(
                        employee.getTeam() != null ? employee.getTeam().getName() : null
                )
                .position(employee.getPosition().name())
                .role(employee.getRole())
                .hireDate(employee.getHireDate())
                .phone(employee.getPhone())
                .isActive(employee.getIsActive())
                .createdAt(employee.getCreatedAt())
                .build();
    }
}
