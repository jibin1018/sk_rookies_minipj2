package com.company.portal.dto.request;

import com.company.portal.enums.Position;
import com.company.portal.enums.Role;
import jakarta.validation.constraints.Email;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmployeeUpdateRequest {

    private String name;

    @Email(message = "올바른 이메일 형식이 아닙니다")
    private String email;

    private Long departmentId;

    private Long teamId;

    private Position position;  // ← Enum으로 변경

    private Role role;

    private LocalDate hireDate;

    private String phone;

    private Boolean isActive;
}