package com.company.portal.dto.request;

import java.time.LocalDate;

import com.company.portal.enums.Position;
import com.company.portal.enums.Role;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignupRequest {

    @NotBlank(message = "사번을 입력해주세요")
    private String employeeId;

    @NotBlank(message = "비밀번호를 입력해주세요")
    private String password;

    @NotBlank(message = "이름을 입력해주세요")
    private String name;

    @NotBlank(message = "이메일을 입력해주세요")
    @Email(message = "올바른 이메일 형식이 아닙니다")
    private String email;

    @NotNull(message = "부서를 선택해주세요")
    private Long departmentId;

    private Long teamId;

    private Position position;

    private Role role;

    private LocalDate hireDate;

    private String phone;
}
