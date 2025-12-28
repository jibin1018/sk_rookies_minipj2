package com.company.portal.dto.request;

import java.time.LocalDate;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MenuRequest {

    @NotNull(message = "날짜를 선택해주세요")
    private LocalDate menuDate;

    @NotBlank(message = "식사 구분을 선택해주세요")
    private String mealType;

    @NotBlank(message = "메뉴를 입력해주세요")
    private String menuItems;

    private Integer calories;
}
