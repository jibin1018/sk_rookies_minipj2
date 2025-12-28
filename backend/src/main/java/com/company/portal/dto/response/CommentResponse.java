package com.company.portal.dto.response;

import java.time.LocalDateTime;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CommentResponse {

    private Long id;
    private String content;
    private String authorName;
    private Long authorId;
    private Long parentId;
    private List<CommentResponse> replies;
    private LocalDateTime createdAt;
}
