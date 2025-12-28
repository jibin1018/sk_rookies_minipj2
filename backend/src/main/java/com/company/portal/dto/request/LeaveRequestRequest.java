package com.company.portal.dto.request;

import java.time.LocalDate;

import com.company.portal.enums.LeaveType;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LeaveRequestRequest {

    @NotNull(message = "휴가 종류를 선택해주세요")
    private LeaveType leaveType;

    @NotNull(message = "시작일을 선택해주세요")
    private LocalDate startDate;

    @NotNull(message = "종료일을 선택해주세요")
    private LocalDate endDate;

    private String reason;

    @NotNull(message = "결재자를 선택해주세요")
    private Long approverId;
}
