package com.company.portal.service.common;

import com.company.portal.dto.request.MenuRequest;
import com.company.portal.dto.request.MenuReviewRequest;
import com.company.portal.entity.CafeteriaMenu;
import com.company.portal.entity.Employee;
import com.company.portal.entity.MenuReview;
import com.company.portal.exception.BadRequestException;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.repository.CafeteriaMenuRepository;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.repository.MenuReviewRepository;
import com.company.portal.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class CafeteriaService {

    private final CafeteriaMenuRepository menuRepository;
    private final MenuReviewRepository reviewRepository;
    private final EmployeeRepository employeeRepository;

    @Transactional
    public CafeteriaMenu createMenu(MenuRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee creator = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        // 중복 체크
        if (menuRepository.findByMenuDateAndMealType(request.getMenuDate(), request.getMealType()).isPresent()) {
            throw new BadRequestException("해당 날짜에 이미 식단이 등록되어 있습니다");
        }

        CafeteriaMenu menu = CafeteriaMenu.builder()
                .menuDate(request.getMenuDate())
                .mealType(request.getMealType())
                .menuItems(request.getMenuItems())
                .calories(request.getCalories())
                .createdBy(creator)
                .build();

        CafeteriaMenu savedMenu = menuRepository.save(menu);

        log.info("식단 등록 성공: date={}, mealType={}", request.getMenuDate(), request.getMealType());

        return savedMenu;
    }

    @Transactional(readOnly = true)
    public List<CafeteriaMenu> getMenusByDate(LocalDate date) {
        return menuRepository.findByMenuDate(date);
    }

    @Transactional(readOnly = true)
    public List<CafeteriaMenu> getMenusByDateRange(LocalDate startDate, LocalDate endDate) {
        return menuRepository.findByMenuDateBetween(startDate, endDate);
    }

    @Transactional
    public CafeteriaMenu updateMenu(Long id, MenuRequest request) {
        CafeteriaMenu menu = menuRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("식단을 찾을 수 없습니다"));

        menu.setMenuDate(request.getMenuDate());
        menu.setMealType(request.getMealType());
        menu.setMenuItems(request.getMenuItems());
        menu.setCalories(request.getCalories());

        CafeteriaMenu updatedMenu = menuRepository.save(menu);

        log.info("식단 수정 성공: id={}", id);

        return updatedMenu;
    }

    @Transactional
    public void deleteMenu(Long id) {
        CafeteriaMenu menu = menuRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("식단을 찾을 수 없습니다"));

        menuRepository.delete(menu);

        log.info("식단 삭제 성공: id={}", id);
    }

    @Transactional
    public MenuReview createReview(Long menuId, MenuReviewRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        CafeteriaMenu menu = menuRepository.findById(menuId)
                .orElseThrow(() -> new ResourceNotFoundException("식단을 찾을 수 없습니다"));

        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        // 중복 평가 체크
        if (reviewRepository.findByMenuIdAndEmployeeId(menuId, currentEmployeeId).isPresent()) {
            throw new BadRequestException("이미 평가한 식단입니다");
        }

        MenuReview review = MenuReview.builder()
                .menu(menu)
                .employee(employee)
                .rating(request.getRating())
                .comment(request.getComment())
                .build();

        MenuReview savedReview = reviewRepository.save(review);

        log.info("식단 평가 성공: menu={}, rating={}", menuId, request.getRating());

        return savedReview;
    }

    @Transactional(readOnly = true)
    public List<MenuReview> getReviewsByMenu(Long menuId) {
        return reviewRepository.findByMenuId(menuId);
    }

    @Transactional(readOnly = true)
    public Double getAverageRating(Long menuId) {
        return reviewRepository.getAverageRatingByMenuId(menuId);
    }
}
