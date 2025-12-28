package com.company.portal.service.common;

import com.company.portal.dto.request.SuggestionRequest;
import com.company.portal.entity.Suggestion;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.repository.SuggestionRepository;
import com.company.portal.util.HashUtil;
import com.company.portal.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class SuggestionService {

    private final SuggestionRepository suggestionRepository;
    private final HashUtil hashUtil;

    @Transactional
    public Suggestion createSuggestion(SuggestionRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        // 익명 ID 생성 (해시 사용)
        String anonymousId = hashUtil.generateAnonymousId(currentEmployeeId, "suggestion");

        Suggestion suggestion = Suggestion.builder()
                .title(request.getTitle())
                .content(request.getContent())
                .anonymousId(anonymousId)
                .status("SUBMITTED")
                .build();

        Suggestion savedSuggestion = suggestionRepository.save(suggestion);

        log.info("건의사항 작성 성공: id={}", savedSuggestion.getId());

        return savedSuggestion;
    }

    @Transactional(readOnly = true)
    public Page<Suggestion> getAllSuggestions(Pageable pageable) {
        return suggestionRepository.findAllByOrderByCreatedAtDesc(pageable);
    }

    @Transactional(readOnly = true)
    public Page<Suggestion> getSuggestionsByStatus(String status, Pageable pageable) {
        return suggestionRepository.findByStatus(status, pageable);
    }

    @Transactional(readOnly = true)
    public List<Suggestion> getMySuggestions() {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        String anonymousId = hashUtil.generateAnonymousId(currentEmployeeId, "suggestion");

        return suggestionRepository.findByAnonymousId(anonymousId);
    }

    @Transactional(readOnly = true)
    public Suggestion getSuggestion(Long id) {
        return suggestionRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("건의사항을 찾을 수 없습니다"));
    }

    @Transactional
    public Suggestion updateStatus(Long id, String status, String reply) {
        Suggestion suggestion = suggestionRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("건의사항을 찾을 수 없습니다"));

        suggestion.setStatus(status);
        if (reply != null) {
            suggestion.setAdminReply(reply);
            suggestion.setRepliedAt(java.time.LocalDateTime.now());
        }

        Suggestion updatedSuggestion = suggestionRepository.save(suggestion);

        log.info("건의사항 상태 변경: id={}, status={}", id, status);

        return updatedSuggestion;
    }
}
