package com.company.portal.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.company.portal.entity.Approval;
import com.company.portal.enums.ApprovalStatus;

@Repository
public interface ApprovalRepository extends JpaRepository<Approval, Long> {

    Page<Approval> findByRequesterId(Long requesterId, Pageable pageable);

    Page<Approval> findByRequesterIdAndStatus(Long requesterId, ApprovalStatus status, Pageable pageable);
}
