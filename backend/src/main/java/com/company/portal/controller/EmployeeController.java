package com.company.portal.controller;

import com.company.portal.dto.request.EmployeeCreateRequest;
import com.company.portal.dto.request.EmployeeUpdateRequest;
import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.EmployeeResponse;
import com.company.portal.service.EmployeeService;
import com.company.portal.service.common.EmployeeQueryService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/employees")
@RequiredArgsConstructor
public class EmployeeController {

    private final EmployeeService employeeService;
    private final EmployeeQueryService employeeQueryService;

    // 관리자 전용 - 전체 사원 관리
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<EmployeeResponse>>> getAllEmployees() {
        List<EmployeeResponse> employees = employeeService.getAllEmployees();
        return ResponseEntity.ok(ApiResponse.success(employees));
    }

    // 모든 사용자 접근 가능 - 결재자 선택용
    @GetMapping("/approvers")
    public ResponseEntity<ApiResponse<List<EmployeeResponse>>> getApprovers() {
        log.info("결재자 목록 조회 요청");
        List<EmployeeResponse> employees = employeeQueryService.getAllEmployees();
        log.info("결재자 목록 조회 완료: {} 명", employees.size());
        return ResponseEntity.ok(ApiResponse.success(employees));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<EmployeeResponse>> getEmployee(@PathVariable Long id) {
        EmployeeResponse employee = employeeService.getEmployee(id);
        return ResponseEntity.ok(ApiResponse.success(employee));
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<EmployeeResponse>> createEmployee(
            @Valid @RequestBody EmployeeCreateRequest request) {
        EmployeeResponse employee = employeeService.createEmployee(request);
        return ResponseEntity.ok(ApiResponse.success("사원 생성 성공", employee));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<EmployeeResponse>> updateEmployee(
            @PathVariable Long id,
            @Valid @RequestBody EmployeeUpdateRequest request) {
        EmployeeResponse employee = employeeService.updateEmployee(id, request);
        return ResponseEntity.ok(ApiResponse.success("사원 정보 수정 성공", employee));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> deleteEmployee(@PathVariable Long id) {
        employeeService.deleteEmployee(id);
        return ResponseEntity.ok(ApiResponse.success("사원 삭제 성공", null));
    }
}
