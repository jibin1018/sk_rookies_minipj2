package com.company.portal.dto.request;

import java.util.List;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApprovalRequest {

    @NotBlank(message = "문서 유형을 선택해주세요")
    private String documentType;

    @NotBlank(message = "제목을 입력해주세요")
    private String title;

    @NotBlank(message = "내용을 입력해주세요")
    private String content;

    @NotEmpty(message = "결재자를 선택해주세요")
    private List<Long> approverIds;  // 결재선 (순서대로)
}
