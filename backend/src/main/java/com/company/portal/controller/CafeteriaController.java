package com.company.portal.controller;

import com.company.portal.dto.request.MenuRequest;
import com.company.portal.dto.request.MenuReviewRequest;
import com.company.portal.dto.response.ApiResponse;
import com.company.portal.entity.CafeteriaMenu;
import com.company.portal.entity.MenuReview;
import com.company.portal.service.common.CafeteriaService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;

@RestController
@RequestMapping("/api/cafeteria")
@RequiredArgsConstructor
public class CafeteriaController {

    private final CafeteriaService cafeteriaService;

    @PostMapping("/menus")
    public ResponseEntity<ApiResponse<CafeteriaMenu>> createMenu(
            @Valid @RequestBody MenuRequest request) {
        CafeteriaMenu menu = cafeteriaService.createMenu(request);
        return ResponseEntity.ok(ApiResponse.success("식단 등록 성공", menu));
    }

    @GetMapping("/menus")
    public ResponseEntity<ApiResponse<List<CafeteriaMenu>>> getMenusByDate(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {
        List<CafeteriaMenu> menus = cafeteriaService.getMenusByDate(date);
        return ResponseEntity.ok(ApiResponse.success(menus));
    }

    @GetMapping("/menus/range")
    public ResponseEntity<ApiResponse<List<CafeteriaMenu>>> getMenusByDateRange(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate) {
        List<CafeteriaMenu> menus = cafeteriaService.getMenusByDateRange(startDate, endDate);
        return ResponseEntity.ok(ApiResponse.success(menus));
    }

    @PutMapping("/menus/{id}")
    public ResponseEntity<ApiResponse<CafeteriaMenu>> updateMenu(
            @PathVariable Long id,
            @Valid @RequestBody MenuRequest request) {
        CafeteriaMenu menu = cafeteriaService.updateMenu(id, request);
        return ResponseEntity.ok(ApiResponse.success("식단 수정 성공", menu));
    }

    @DeleteMapping("/menus/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteMenu(@PathVariable Long id) {
        cafeteriaService.deleteMenu(id);
        return ResponseEntity.ok(ApiResponse.success("식단 삭제 성공", null));
    }

    @PostMapping("/menus/{menuId}/reviews")
    public ResponseEntity<ApiResponse<MenuReview>> createReview(
            @PathVariable Long menuId,
            @Valid @RequestBody MenuReviewRequest request) {
        MenuReview review = cafeteriaService.createReview(menuId, request);
        return ResponseEntity.ok(ApiResponse.success("평가 등록 성공", review));
    }

    @GetMapping("/menus/{menuId}/reviews")
    public ResponseEntity<ApiResponse<List<MenuReview>>> getReviewsByMenu(
            @PathVariable Long menuId) {
        List<MenuReview> reviews = cafeteriaService.getReviewsByMenu(menuId);
        return ResponseEntity.ok(ApiResponse.success(reviews));
    }

    @GetMapping("/menus/{menuId}/rating")
    public ResponseEntity<ApiResponse<Double>> getAverageRating(@PathVariable Long menuId) {
        Double rating = cafeteriaService.getAverageRating(menuId);
        return ResponseEntity.ok(ApiResponse.success(rating));
    }
}
