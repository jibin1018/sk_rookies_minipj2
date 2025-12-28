package com.company.portal.entity;

import com.company.portal.enums.ApprovalStatus;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "approval_lines")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApprovalLine {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "approval_id", nullable = false)
    private Approval approval;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "approver_id", nullable = false)
    private Employee approver;

    @Column(name = "step_order", nullable = false)
    private Integer stepOrder;  // 결재 순서

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    @Builder.Default
    private ApprovalStatus status = ApprovalStatus.PENDING;

    @Column(columnDefinition = "TEXT")
    private String comment;  // 결재 의견

    @Column(name = "approved_at")
    private LocalDateTime approvedAt;
}
