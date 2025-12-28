package com.company.portal.repository;

import com.company.portal.entity.CompanyBoard;
import com.company.portal.enums.BoardCategory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CompanyBoardRepository extends JpaRepository<CompanyBoard, Long> {

    Page<CompanyBoard> findByCategory(BoardCategory category, Pageable pageable);

    Page<CompanyBoard> findByIsNoticeTrue(Pageable pageable);

    @Query("SELECT b FROM CompanyBoard b WHERE b.title LIKE %:keyword% OR b.content LIKE %:keyword%")
    Page<CompanyBoard> searchByKeyword(@Param("keyword") String keyword, Pageable pageable);

    @Query("SELECT b FROM CompanyBoard b WHERE b.category = :category AND (b.title LIKE %:keyword% OR b.content LIKE %:keyword%)")
    Page<CompanyBoard> searchByCategoryAndKeyword(@Param("category") BoardCategory category, @Param("keyword") String keyword, Pageable pageable);
}
