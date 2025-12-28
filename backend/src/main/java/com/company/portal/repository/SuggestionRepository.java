package com.company.portal.repository;

import com.company.portal.entity.Suggestion;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SuggestionRepository extends JpaRepository<Suggestion, Long> {

    List<Suggestion> findByAnonymousId(String anonymousId);

    Page<Suggestion> findByStatus(String status, Pageable pageable);

    Page<Suggestion> findAllByOrderByCreatedAtDesc(Pageable pageable);
}
