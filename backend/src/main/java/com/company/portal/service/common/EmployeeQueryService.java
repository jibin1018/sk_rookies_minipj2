package com.company.portal.service.common;

import com.company.portal.dto.response.EmployeeResponse;
import com.company.portal.entity.Employee;
import com.company.portal.repository.EmployeeRepository;
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
    public List<EmployeeResponse> getAllEmployees() {
        return employeeRepository.findAll().stream()
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
                .departmentId(employee.getDepartment() != null ? employee.getDepartment().getId() : null)
                .teamName(employee.getTeam() != null ? employee.getTeam().getName() : null)
                .teamId(employee.getTeam() != null ? employee.getTeam().getId() : null)
                .position(employee.getPosition())
                .role(employee.getRole())
                .hireDate(employee.getHireDate())
                .phone(employee.getPhone())
                .isActive(employee.getIsActive())
                .createdAt(employee.getCreatedAt())
                .build();
    }
}
