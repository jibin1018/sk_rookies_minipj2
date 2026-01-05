package com.company.portal.dto.request;

import java.time.LocalDateTime;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ScheduleRequest {

    @NotBlank(message = "제목을 입력해주세요")
    private String title;

    private String content;

    @NotNull(message = "시작 날짜를 선택해주세요")
    private LocalDateTime startDate;

    @NotNull(message = "종료 날짜를 선택해주세요")
    private LocalDateTime endDate;

    private Long assigneeId;
}
