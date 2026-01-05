package com.company.portal.service;

import com.company.portal.dto.request.BoardRequest;
import com.company.portal.dto.request.CommentRequest;
import com.company.portal.dto.response.BoardResponse;
import com.company.portal.dto.response.CommentResponse;
import com.company.portal.dto.response.FileResponse;
import com.company.portal.entity.Comment;
import com.company.portal.entity.CompanyBoard;
import com.company.portal.entity.Employee;
import com.company.portal.entity.SecurityLog;
import com.company.portal.exception.BadRequestException;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.repository.CommentRepository;
import com.company.portal.repository.CompanyBoardRepository;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.repository.SecurityLogRepository;
import com.company.portal.util.SecurityUtil;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class BoardService {

    private final CompanyBoardRepository boardRepository;
    private final CommentRepository commentRepository;
    private final EmployeeRepository employeeRepository;
    private final SecurityLogRepository securityLogRepository;
    private final EntityManager entityManager;

    @Transactional
    public BoardResponse createBoard(BoardRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        Employee author = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        // XSS 취약점 - 입력값 검증 없이 그대로 저장
        String title = request.getTitle();
        String content = request.getContent();

        // XSS 패턴 감지 시 로그 기록
        if (title.contains("<script") || content.contains("<script")) {
            logSecurityEvent("XSS_STORED", "XSS payload detected in board creation: " + title);
        }

        CompanyBoard board = CompanyBoard.builder()
                .category(request.getCategory()) // Enum 타입 그대로 사용
                .title(title)
                .content(content)
                .author(author)
                .isNotice(request.getIsNotice())
                .views(0)
                .likes(0)
                .build();

        CompanyBoard savedBoard = boardRepository.save(board);

        log.warn("Vulnerable 모드 - 게시글 작성 (XSS 가능): {}", savedBoard.getId());

        return convertToResponse(savedBoard);
    }

    @Transactional(readOnly = true)
    public Page<BoardResponse> getBoards(Pageable pageable) {
        return boardRepository.findAll(pageable)
                .map(this::convertToResponse);
    }

    @Transactional(readOnly = true)
    public Page<BoardResponse> searchBoards(String keyword, Pageable pageable) {
        // SQL Injection 취약점 - 문자열 연결
        String sql = "SELECT b FROM CompanyBoard b WHERE b.title LIKE '%"
                + keyword + "%' OR b.content LIKE '%" + keyword + "%'";

        log.warn("Vulnerable 모드 - SQL Injection 가능한 검색: {}", sql);

        try {
            Query query = entityManager.createQuery(sql);
            query.setFirstResult((int) pageable.getOffset());
            query.setMaxResults(pageable.getPageSize());

            @SuppressWarnings("unchecked")
            List<CompanyBoard> results = query.getResultList();

            // SQL Injection 시도 감지
            if (keyword.contains("'") || keyword.contains("--") || keyword.contains("OR")) {
                logSecurityEvent("SQL_INJECTION_ATTEMPT", "SQL Injection attempt in search: " + keyword);
            }

            List<BoardResponse> responses = results.stream()
                    .map(this::convertToResponse)
                    .collect(Collectors.toList());

            return new PageImpl<>(responses, pageable, results.size());

        } catch (Exception e) {
            log.error("Vulnerable 모드 - 검색 오류: ", e);
            throw new BadRequestException("검색 실패: " + e.getMessage());
        }
    }

    @Transactional
    public BoardResponse getBoard(Long id) {
        CompanyBoard board = boardRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("게시글을 찾을 수 없습니다"));

        // 조회수 증가
        board.setViews(board.getViews() + 1);
        boardRepository.save(board);

        return convertToResponse(board);
    }

    @Transactional
    public BoardResponse updateBoard(Long id, BoardRequest request) {
        CompanyBoard board = boardRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("게시글을 찾을 수 없습니다"));

        // 권한 체크 없음 - 누구나 수정 가능
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        if (!board.getAuthor().getId().equals(currentEmployeeId)) {
            log.warn("Vulnerable 모드 - 권한 없는 수정 성공! board={}, employee={}", id, currentEmployeeId);
            logSecurityEvent("UNAUTHORIZED_MODIFICATION",
                    "Unauthorized board modification: board=" + id + ", employee=" + currentEmployeeId);
        }

        // XSS 취약점
        board.setTitle(request.getTitle());
        board.setContent(request.getContent());
        board.setCategory(request.getCategory());  // Enum 타입 그대로 사용

        CompanyBoard updatedBoard = boardRepository.save(board);

        log.warn("Vulnerable 모드 - 게시글 수정 (권한 체크 없음): {}", id);

        return convertToResponse(updatedBoard);
    }

    @Transactional
    public void deleteBoard(Long id) {
        CompanyBoard board = boardRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("게시글을 찾을 수 없습니다"));

        // 권한 체크 없음 - 누구나 삭제 가능
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        if (!board.getAuthor().getId().equals(currentEmployeeId)) {
            log.warn("Vulnerable 모드 - 권한 없는 삭제 성공! board={}, employee={}", id, currentEmployeeId);
            logSecurityEvent("UNAUTHORIZED_DELETION",
                    "Unauthorized board deletion: board=" + id + ", employee=" + currentEmployeeId);
        }

        boardRepository.delete(board);

        log.warn("Vulnerable 모드 - 게시글 삭제 (권한 체크 없음): {}", id);
    }

    @Transactional
    public CommentResponse createComment(Long boardId, CommentRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        CompanyBoard board = boardRepository.findById(boardId)
                .orElseThrow(() -> new ResourceNotFoundException("게시글을 찾을 수 없습니다"));

        Employee author = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        // XSS 취약점 - 검증 없이 저장
        String content = request.getContent();

        if (content.contains("<script")) {
            logSecurityEvent("XSS_COMMENT", "XSS payload in comment: " + content);
        }

        Comment parent = null;
        if (request.getParentId() != null) {
            parent = commentRepository.findById(request.getParentId())
                    .orElseThrow(() -> new ResourceNotFoundException("부모 댓글을 찾을 수 없습니다"));
        }

        Comment comment = Comment.builder()
                .board(board)
                .parent(parent)
                .content(content)
                .author(author)
                .build();

        Comment savedComment = commentRepository.save(comment);

        log.warn("Vulnerable 모드 - 댓글 작성 (XSS 가능): {}", savedComment.getId());

        return convertCommentToResponse(savedComment);
    }

    @Transactional(readOnly = true)
    public List<CommentResponse> getComments(Long boardId) {
        List<Comment> comments = commentRepository.findByBoardIdAndParentIsNull(boardId);
        return comments.stream()
                .map(this::convertCommentToResponse)
                .collect(Collectors.toList());
    }

    @Transactional
    public void deleteComment(Long commentId) {
        Comment comment = commentRepository.findById(commentId)
                .orElseThrow(() -> new ResourceNotFoundException("댓글을 찾을 수 없습니다"));

        // 권한 체크 없음
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        if (!comment.getAuthor().getId().equals(currentEmployeeId)) {
            log.warn("Vulnerable 모드 - 권한 없는 댓글 삭제 성공!");
            logSecurityEvent("UNAUTHORIZED_COMMENT_DELETION",
                    "Unauthorized comment deletion: comment=" + commentId);
        }

        commentRepository.delete(comment);

        log.warn("Vulnerable 모드 - 댓글 삭제 (권한 체크 없음): {}", commentId);
    }

    private void logSecurityEvent(String attackType, String details) {
        SecurityLog securityLog = SecurityLog.builder()
                .attackType(attackType)
                .securityMode("vulnerable")
                .details(details)
                .build();

        securityLogRepository.save(securityLog);
    }

    private BoardResponse convertToResponse(CompanyBoard board) {
        long commentCount = commentRepository.countByBoardId(board.getId());

        List<FileResponse> files = board.getFiles().stream()
                .map(file -> FileResponse.builder()
                .id(file.getId())
                .originalName(file.getOriginalName())
                .storedName(file.getStoredName())
                .fileSize(file.getFileSize())
                .downloadUrl("/api/files/" + file.getId())
                .build())
                .collect(Collectors.toList());

        return BoardResponse.builder()
                .id(board.getId())
                .category(board.getCategory()) // Enum 타입 그대로 반환
                .title(board.getTitle())
                .content(board.getContent())
                .authorName(board.getAuthor().getName())
                .authorId(board.getAuthor().getId())
                .views(board.getViews())
                .likes(board.getLikes())
                .isNotice(board.getIsNotice())
                .commentCount((int) commentCount)
                .files(files)
                .createdAt(board.getCreatedAt())
                .updatedAt(board.getUpdatedAt())
                .build();
    }

    private CommentResponse convertCommentToResponse(Comment comment) {
        List<CommentResponse> replies = comment.getReplies().stream()
                .map(this::convertCommentToResponse)
                .collect(Collectors.toList());

        return CommentResponse.builder()
                .id(comment.getId())
                .content(comment.getContent())
                .authorName(comment.getAuthor().getName())
                .authorId(comment.getAuthor().getId())
                .parentId(comment.getParent() != null ? comment.getParent().getId() : null)
                .replies(replies)
                .createdAt(comment.getCreatedAt())
                .build();
    }
}
