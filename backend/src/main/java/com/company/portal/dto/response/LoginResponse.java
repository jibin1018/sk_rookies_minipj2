package com.company.portal.dto.response;

import com.company.portal.enums.Position;
import com.company.portal.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginResponse {

    private String token;
    private String tokenType = "Bearer";
    private Long id;
    private String employeeId;
    private String name;
    private String email;
    private String departmentName;
    private String teamName;
    private Position position;
    private Role role;
}
