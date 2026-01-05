package com.company.portal.service.common;

import com.company.portal.entity.CafeteriaMenu;
import com.company.portal.entity.Employee;
import com.company.portal.repository.CafeteriaMenuRepository;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;

@Service
@RequiredArgsConstructor
public class CafeteriaService {
    
    private final CafeteriaMenuRepository cafeteriaMenuRepository;
    private final EmployeeRepository employeeRepository;
    
    @Transactional(readOnly = true)
    public List<CafeteriaMenu> getMenusByDate(LocalDate date) {
        return cafeteriaMenuRepository.findByMenuDate(date);
    }

       
    @Transactional(readOnly = true)
    public List<CafeteriaMenu> getWeeklyMenus(LocalDate startDate, LocalDate endDate) {

           return cafeteriaMenuRepository.findByMenuDateBetween(startDate, endDate);
    }
    
           @Transactional
    public CafeteriaMenu createMenu(CafeteriaMenu menu) {
               Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다"));
        
               menu.setCreatedBy(employee.getId());  // ✅ 이렇게 수정
        return cafeteriaMenuRepository.save(menu);
    }
}                        
    
    
                                    
                    
                                                            
    
    
