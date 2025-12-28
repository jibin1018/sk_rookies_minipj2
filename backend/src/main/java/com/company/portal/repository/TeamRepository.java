package com.company.portal.repository;

import com.company.portal.entity.Team;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TeamRepository extends JpaRepository<Team, Long> {

    List<Team> findByDepartmentId(Long departmentId);

    boolean existsByName(String name);
}
