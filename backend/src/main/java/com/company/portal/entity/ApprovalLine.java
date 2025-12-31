package com.company.portal.entity;

import com.company.portal.enums.ApprovalStatus;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "approval_lines")
@Data  // ← @Getter, @Setter 대신 @Data 사용
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApprovalLine extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "approval_id", nullable = false)
    private Approval approval;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "approver_id", nullable = false)
    private Employee approver;

    @Column(nullable = false, name = "approval_order")
    private Integer approvalOrder;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private ApprovalStatus status = ApprovalStatus.PENDING;

    private LocalDateTime approvedAt;

    private LocalDateTime rejectedAt;

    private String comment;
}
