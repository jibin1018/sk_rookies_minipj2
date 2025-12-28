package com.company.portal.security;

import com.company.portal.entity.Employee;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@Getter
public class CustomUserDetails implements UserDetails {

    private final Long id;
    private final String employeeId;
    private final String password;
    private final String name;
    private final Collection<? extends GrantedAuthority> authorities;
    private final boolean isActive;

    public CustomUserDetails(Employee employee) {
        this.id = employee.getId();
        this.employeeId = employee.getEmployeeId();
        this.password = employee.getPassword();
        this.name = employee.getName();
        this.authorities = Collections.singletonList(
                new SimpleGrantedAuthority("ROLE_" + employee.getRole().name())
        );
        this.isActive = employee.getIsActive();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return employeeId;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return isActive;
    }
}
