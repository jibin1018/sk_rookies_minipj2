package com.company.portal.repository;

import com.company.portal.entity.CafeteriaMenu;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;

@Repository
public interface CafeteriaMenuRepository extends JpaRepository<CafeteriaMenu, Long> {

    @Query("SELECT cm FROM CafeteriaMenu cm WHERE cm.menuDate = :date ORDER BY CASE WHEN cm.mealType = '중식' THEN 1 WHEN cm.mealType = '석식' THEN 2 ELSE 3 END")
    List<CafeteriaMenu> findByMenuDate(@Param("date") LocalDate date);

    List<CafeteriaMenu> findByMenuDateBetween(LocalDate startDate, LocalDate endDate);
}
