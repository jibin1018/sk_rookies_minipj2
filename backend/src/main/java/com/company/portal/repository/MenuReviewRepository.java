package com.company.portal.repository;

import com.company.portal.entity.MenuReview;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface MenuReviewRepository extends JpaRepository<MenuReview, Long> {

    List<MenuReview> findByMenuId(Long menuId);

    Optional<MenuReview> findByMenuIdAndEmployeeId(Long menuId, Long employeeId);

    @Query("SELECT AVG(r.rating) FROM MenuReview r WHERE r.menu.id = :menuId")
    Double getAverageRatingByMenuId(@Param("menuId") Long menuId);
}
