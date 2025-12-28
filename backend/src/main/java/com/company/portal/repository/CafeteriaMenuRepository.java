package com.company.portal.repository;

import com.company.portal.entity.CafeteriaMenu;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

@Repository
public interface CafeteriaMenuRepository extends JpaRepository<CafeteriaMenu, Long> {

    List<CafeteriaMenu> findByMenuDate(LocalDate menuDate);

    Optional<CafeteriaMenu> findByMenuDateAndMealType(LocalDate menuDate, String mealType);

    List<CafeteriaMenu> findByMenuDateBetween(LocalDate startDate, LocalDate endDate);
}
