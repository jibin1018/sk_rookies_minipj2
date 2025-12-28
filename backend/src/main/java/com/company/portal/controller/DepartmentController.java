package com.company.portal.controller;

import com.company.portal.dto.response.ApiResponse;
import com.company.portal.entity.Department;
import com.company.portal.service.common.DepartmentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/departments")
@RequiredArgsConstructor
public class DepartmentController {

    private final DepartmentService departmentService;

    @GetMapping
    public ResponseEntity<ApiResponse<List<Department>>> getAllDepartments() {
        List<Department> departments = departmentService.getAllDepartments();
        return ResponseEntity.ok(ApiResponse.success(departments));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<Department>> getDepartment(@PathVariable Long id) {
        Department department = departmentService.getDepartment(id);
        return ResponseEntity.ok(ApiResponse.success(department));
    }
}
