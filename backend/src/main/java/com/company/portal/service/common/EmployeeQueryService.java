package com.company.portal.service.common;

import com.company.portal.dto.response.EmployeeResponse;
import com.company.portal.entity.Employee;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmployeeQueryService {

    private final EmployeeRepository employeeRepository;

    @Transactional(readOnly = true)
    public EmployeeResponse getCurrentEmployee() {
        Long employeeId = SecurityUtil.getCurrentEmployeeId();
        Employee employee = employeeRepository.findById(employeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        return convertToResponse(employee);
    }

    @Transactional(readOnly = true)
    public EmployeeResponse getEmployee(Long id) {
        Employee employee = employeeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        return convertToResponse(employee);
    }

    @Transactional(readOnly = true)
    public List<EmployeeResponse> getAllEmployees() {
        return employeeRepository.findAll().stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<EmployeeResponse> getEmployeesByDepartment(Long departmentId) {
        return employeeRepository.findAll().stream()
                .filter(e -> e.getDepartment() != null && e.getDepartment().getId().equals(departmentId))
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<EmployeeResponse> getEmployeesByTeam(Long teamId) {
        return employeeRepository.findAll().stream()
                .filter(e -> e.getTeam() != null && e.getTeam().getId().equals(teamId))
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    private EmployeeResponse convertToResponse(Employee employee) {
        return EmployeeResponse.builder()
                .id(employee.getId())
                .employeeId(employee.getEmployeeId())
                .name(employee.getName())
                .email(employee.getEmail())
                .departmentName(employee.getDepartment() != null ? employee.getDepartment().getName() : null)
                .teamName(employee.getTeam() != null ? employee.getTeam().getName() : null)
                .position(employee.getPosition().name())
                .role(employee.getRole())
                .hireDate(employee.getHireDate())
                .phone(employee.getPhone())
                .isActive(employee.getIsActive())
                .build();
    }
}
