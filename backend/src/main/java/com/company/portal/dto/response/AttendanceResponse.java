package com.company.portal.dto.response;

import java.time.LocalDate;
import java.time.LocalDateTime;

import com.company.portal.enums.AttendanceStatus;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AttendanceResponse {

    private Long id;
    private String employeeName;
    private LocalDate workDate;
    private LocalDateTime checkIn;
    private LocalDateTime checkOut;
    private AttendanceStatus status;
    private String note;
}
