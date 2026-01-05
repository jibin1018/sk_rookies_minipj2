package com.company.portal.controller;

import com.company.portal.dto.response.ApiResponse;
import com.company.portal.entity.CafeteriaMenu;
import com.company.portal.repository.CafeteriaMenuRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/cafeteria")
@RequiredArgsConstructor
public class CafeteriaController {

    private final CafeteriaMenuRepository cafeteriaMenuRepository;

    @GetMapping("/menus")
    public ResponseEntity<ApiResponse<List<CafeteriaMenu>>> getMenusByDate(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {

        log.info("식단 조회 - 날짜: {}", date);
        List<CafeteriaMenu> menus = cafeteriaMenuRepository.findByMenuDate(date);
        log.info("조회된 식단 개수: {}", menus.size());

        return ResponseEntity.ok(ApiResponse.success("조회 성공", menus));
    }
}
