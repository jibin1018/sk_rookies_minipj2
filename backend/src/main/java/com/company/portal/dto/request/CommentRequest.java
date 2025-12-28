package com.company.portal.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CommentRequest {

    @NotBlank(message = "댓글 내용을 입력해주세요")
    private String content;

    private Long parentId;  // 대댓글인 경우
}
