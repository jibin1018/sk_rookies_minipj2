package com.company.portal.service.secure;

import com.company.portal.dto.request.BoardRequest;
import com.company.portal.dto.request.CommentRequest;
import com.company.portal.dto.response.BoardResponse;
import com.company.portal.dto.response.CommentResponse;
import com.company.portal.dto.response.FileResponse;
import com.company.portal.entity.Comment;
import com.company.portal.entity.CompanyBoard;
import com.company.portal.entity.Employee;
import com.company.portal.exception.BadRequestException;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.exception.UnauthorizedException;
import com.company.portal.repository.CommentRepository;
import com.company.portal.repository.CompanyBoardRepository;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.util.SecurityUtil;
import com.company.portal.util.ValidationUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecureBoardService {

    private final CompanyBoardRepository boardRepository;
    private final CommentRepository commentRepository;
    private final EmployeeRepository employeeRepository;
    private final ValidationUtil validationUtil;

    @Transactional
    public BoardResponse createBoard(BoardRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        Employee author = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        // XSS 방어 - HTML 이스케이프
        String safeTitle = validationUtil.sanitizeInput(request.getTitle());
        String safeContent = validationUtil.sanitizeInput(request.getContent());

        // XSS 패턴 검증
        if (validationUtil.containsXss(request.getTitle()) || validationUtil.containsXss(request.getContent())) {
            log.warn("Secure 모드 - XSS 공격 시도 차단: {}", currentEmployeeId);
            throw new BadRequestException("허용되지 않는 문자가 포함되어 있습니다");
        }

        CompanyBoard board = CompanyBoard.builder()
                .category(request.getCategory())
                .title(safeTitle)
                .content(safeContent)
                .author(author)
                .isNotice(request.getIsNotice())
                .views(0)
                .likes(0)
                .build();

        CompanyBoard savedBoard = boardRepository.save(board);

        log.info("Secure 모드 - 게시글 작성 성공: {}", savedBoard.getId());

        return convertToResponse(savedBoard);
    }

    @Transactional(readOnly = true)
    public Page<BoardResponse> getBoards(Pageable pageable) {
        return boardRepository.findAll(pageable)
                .map(this::convertToResponse);
    }

    @Transactional(readOnly = true)
    public Page<BoardResponse> searchBoards(String keyword, Pageable pageable) {
        // SQL Injection 방어 - JPA 사용
        String safeKeyword = validationUtil.sanitizeInput(keyword);

        return boardRepository.searchByKeyword(safeKeyword, pageable)
                .map(this::convertToResponse);
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
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        CompanyBoard board = boardRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("게시글을 찾을 수 없습니다"));

        // 권한 체크 - 작성자 본인만 ��정 가능
        if (!board.getAuthor().getId().equals(currentEmployeeId)) {
            log.warn("Secure 모드 - 권한 없는 수정 시도 차단: board={}, employee={}", id, currentEmployeeId);
            throw new UnauthorizedException("게시글을 수정할 권한이 없습니다");
        }

        // XSS 방어
        String safeTitle = validationUtil.sanitizeInput(request.getTitle());
        String safeContent = validationUtil.sanitizeInput(request.getContent());

        board.setTitle(safeTitle);
        board.setContent(safeContent);
        board.setCategory(request.getCategory());

        CompanyBoard updatedBoard = boardRepository.save(board);

        log.info("Secure 모드 - 게시글 수정 성공: {}", id);

        return convertToResponse(updatedBoard);
    }

    @Transactional
    public void deleteBoard(Long id) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        CompanyBoard board = boardRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("게시글을 찾을 수 없습니다"));

        // 권한 체크 - 작성자 본인만 삭제 가능
        if (!board.getAuthor().getId().equals(currentEmployeeId)) {
            log.warn("Secure 모드 - 권한 없는 삭제 시도 차단: board={}, employee={}", id, currentEmployeeId);
            throw new UnauthorizedException("게시글을 삭제할 권한이 없습니다");
        }

        boardRepository.delete(board);

        log.info("Secure 모드 - 게시글 삭제 성공: {}", id);
    }

    @Transactional
    public CommentResponse createComment(Long boardId, CommentRequest request) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        CompanyBoard board = boardRepository.findById(boardId)
                .orElseThrow(() -> new ResourceNotFoundException("게시글을 찾을 수 없습니다"));

        Employee author = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        // XSS 방어
        String safeContent = validationUtil.sanitizeInput(request.getContent());

        Comment parent = null;
        if (request.getParentId() != null) {
            parent = commentRepository.findById(request.getParentId())
                    .orElseThrow(() -> new ResourceNotFoundException("부모 댓글을 찾을 수 없습니다"));
        }

        Comment comment = Comment.builder()
                .board(board)
                .parent(parent)
                .content(safeContent)
                .author(author)
                .build();

        Comment savedComment = commentRepository.save(comment);

        log.info("Secure 모드 - 댓글 작성 성공: board={}, comment={}", boardId, savedComment.getId());

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
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Comment comment = commentRepository.findById(commentId)
                .orElseThrow(() -> new ResourceNotFoundException("댓글을 찾을 수 없습니다"));

        // 권한 체크
        if (!comment.getAuthor().getId().equals(currentEmployeeId)) {
            throw new UnauthorizedException("댓글을 삭제할 권한이 없습니다");
        }

        commentRepository.delete(comment);

        log.info("Secure 모드 - 댓글 삭제 성공: {}", commentId);
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
                .category(board.getCategory())
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
