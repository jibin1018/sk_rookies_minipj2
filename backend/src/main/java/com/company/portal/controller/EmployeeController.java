package com.company.portal.controller;

import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.EmployeeResponse;
import com.company.portal.service.common.EmployeeService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/employees")
@RequiredArgsConstructor
public class EmployeeController {

    private final EmployeeService employeeService;

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<EmployeeResponse>> getCurrentEmployee() {
        EmployeeResponse response = employeeService.getCurrentEmployee();
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<EmployeeResponse>> getEmployee(@PathVariable Long id) {
        EmployeeResponse response = employeeService.getEmployee(id);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<EmployeeResponse>>> getAllEmployees() {
        List<EmployeeResponse> response = employeeService.getAllEmployees();
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/department/{departmentId}")
    public ResponseEntity<ApiResponse<List<EmployeeResponse>>> getEmployeesByDepartment(
            @PathVariable Long departmentId) {
        List<EmployeeResponse> response = employeeService.getEmployeesByDepartment(departmentId);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/team/{teamId}")
    public ResponseEntity<ApiResponse<List<EmployeeResponse>>> getEmployeesByTeam(
            @PathVariable Long teamId) {
        List<EmployeeResponse> response = employeeService.getEmployeesByTeam(teamId);
        return ResponseEntity.ok(ApiResponse.success(response));
    }
}
