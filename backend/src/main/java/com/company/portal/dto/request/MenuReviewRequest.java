package com.company.portal.dto.request;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MenuReviewRequest {

    @NotNull(message = "평점을 입력해주세요")
    @Min(value = 1, message = "평점은 1-5 사이여야 합니다")
    @Max(value = 5, message = "평점은 1-5 사이여야 합니다")
    private Integer rating;

    private String comment;
}
