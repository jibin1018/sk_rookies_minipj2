package com.company.portal.dto.request;

import com.company.portal.enums.BoardCategory;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BoardRequest {

    @NotNull(message = "카테고리를 선택해주세요")
    private BoardCategory category;

    @NotBlank(message = "제목을 입력해주세요")
    private String title;

    @NotBlank(message = "내용을 입력해주세요")
    private String content;

    private Boolean isNotice = false;
}
