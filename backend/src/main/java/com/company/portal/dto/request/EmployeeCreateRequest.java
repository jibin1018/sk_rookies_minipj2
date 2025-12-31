package com.company.portal.dto.request;

import com.company.portal.enums.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmployeeCreateRequest {

    @NotBlank(message = "사번은 필수입니다")
    private String employeeId;

    @NotBlank(message = "비밀번호는 필수입니다")
    private String password;

    @NotBlank(message = "이름은 필수입니다")
    private String name;

    @NotBlank(message = "이메일은 필수입니다")
    @Email(message = "올바른 이메일 형식이 아닙니다")
    private String email;

    @NotNull(message = "부서는 필수입니다")
    private Long departmentId;

    private Long teamId;

    @NotBlank(message = "직급은 필수입니다")
    private String position;

    @NotNull(message = "역할은 필수입니다")
    private Role role;

    @NotNull(message = "입사일은 필수입니다")
    private LocalDate hireDate;

    private String phone;
}
