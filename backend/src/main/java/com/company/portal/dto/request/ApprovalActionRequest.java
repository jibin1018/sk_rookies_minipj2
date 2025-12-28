package com.company.portal.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApprovalActionRequest {

    @NotBlank(message = "액션을 선택해주세요")
    private String action;  // APPROVE, REJECT

    private String comment;
}
