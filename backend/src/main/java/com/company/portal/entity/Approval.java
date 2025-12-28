package com.company.portal.entity;

import com.company.portal.enums.ApprovalStatus;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "approvals")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Approval extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "document_type", nullable = false, length = 50)
    private String documentType;  // 휴가신청서, 지출결의서, 구매요청서 등

    @Column(nullable = false, length = 200)
    private String title;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String content;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "requester_id", nullable = false)
    private Employee requester;

    @Column(name = "current_step")
    @Builder.Default
    private Integer currentStep = 1;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    @Builder.Default
    private ApprovalStatus status = ApprovalStatus.PENDING;

    @OneToMany(mappedBy = "approval", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("stepOrder ASC")
    @Builder.Default
    private List<ApprovalLine> approvalLines = new ArrayList<>();
}
