package com.company.portal.dto.response;

import com.company.portal.enums.Position;
import com.company.portal.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmployeeResponse {

    private Long id;
    private String employeeId;
    private String name;
    private String email;
    private String departmentName;
    private Long departmentId;
    private String teamName;
    private Long teamId;
    private Position position;  // ← Enum으로 변경
    private Role role;
    private LocalDate hireDate;
    private String phone;
    private Boolean isActive;
    private LocalDateTime createdAt;
}
