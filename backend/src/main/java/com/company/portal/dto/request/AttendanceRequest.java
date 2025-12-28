package com.company.portal.dto.request;

import java.time.LocalDateTime;

import com.company.portal.enums.AttendanceStatus;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AttendanceRequest {

    private LocalDateTime checkIn;

    private LocalDateTime checkOut;

    private AttendanceStatus status;

    private String note;
}
