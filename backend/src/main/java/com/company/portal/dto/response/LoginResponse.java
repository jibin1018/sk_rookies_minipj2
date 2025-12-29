package com.company.portal.dto.response;

import com.company.portal.enums.Position;
import com.company.portal.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {

    private String token;
    private Long id;
    private String employeeId;
    private String name;
    private String email;
    private Long departmentId;
    private String departmentName;
    private Long teamId;
    private String teamName;
    private Position position;
    private Role role;
}
