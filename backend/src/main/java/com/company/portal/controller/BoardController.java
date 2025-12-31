package com.company.portal.controller;

import com.company.portal.dto.request.BoardRequest;
import com.company.portal.dto.request.CommentRequest;
import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.BoardResponse;
import com.company.portal.dto.response.CommentResponse;
import com.company.portal.service.BoardService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/boards")
@RequiredArgsConstructor
public class BoardController {

    private final BoardService boardService;

    @PostMapping
    public ResponseEntity<ApiResponse<BoardResponse>> createBoard(@Valid @RequestBody BoardRequest request) {
        BoardResponse response = boardService.createBoard(request);
        return ResponseEntity.ok(ApiResponse.success("게시글 작성 성공", response));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<Page<BoardResponse>>> getBoards(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "createdAt") String sort) {

        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, sort));
        Page<BoardResponse> response = boardService.getBoards(pageable);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/search")
    public ResponseEntity<ApiResponse<Page<BoardResponse>>> searchBoards(
            @RequestParam String keyword,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<BoardResponse> response = boardService.searchBoards(keyword, pageable);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<BoardResponse>> getBoard(@PathVariable Long id) {
        BoardResponse response = boardService.getBoard(id);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<BoardResponse>> updateBoard(
            @PathVariable Long id,
            @Valid @RequestBody BoardRequest request) {
        BoardResponse response = boardService.updateBoard(id, request);
        return ResponseEntity.ok(ApiResponse.success("게시글 수정 성공", response));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteBoard(@PathVariable Long id) {
        boardService.deleteBoard(id);
        return ResponseEntity.ok(ApiResponse.success("게시글 삭제 성공", null));
    }

    @PostMapping("/{boardId}/comments")
    public ResponseEntity<ApiResponse<CommentResponse>> createComment(
            @PathVariable Long boardId,
            @Valid @RequestBody CommentRequest request) {
        CommentResponse response = boardService.createComment(boardId, request);
        return ResponseEntity.ok(ApiResponse.success("댓글 작성 성공", response));
    }

    @GetMapping("/{boardId}/comments")
    public ResponseEntity<ApiResponse<List<CommentResponse>>> getComments(@PathVariable Long boardId) {
        List<CommentResponse> response = boardService.getComments(boardId);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @DeleteMapping("/comments/{commentId}")
    public ResponseEntity<ApiResponse<Void>> deleteComment(@PathVariable Long commentId) {
        boardService.deleteComment(commentId);
        return ResponseEntity.ok(ApiResponse.success("댓글 삭제 성공", null));
    }
}
