package com.company.portal.dto.response;

import java.time.LocalDateTime;
import java.util.List;

import com.company.portal.enums.BoardCategory;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BoardResponse {

    private Long id;
    private BoardCategory category;
    private String title;
    private String content;
    private String authorName;
    private Long authorId;
    private Integer views;
    private Integer likes;
    private Boolean isNotice;
    private Integer commentCount;
    private List<FileResponse> files;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
