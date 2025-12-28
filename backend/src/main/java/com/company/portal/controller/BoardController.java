package com.company.portal.controller;

import com.company.portal.dto.request.BoardRequest;
import com.company.portal.dto.request.CommentRequest;
import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.BoardResponse;
import com.company.portal.dto.response.CommentResponse;
import com.company.portal.service.secure.SecureBoardService;
import com.company.portal.service.vulnerable.VulnerableBoardService;
import jakarta.servlet.http.HttpServletRequest;
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

    private final SecureBoardService secureBoardService;
    private final VulnerableBoardService vulnerableBoardService;

    @PostMapping
    public ResponseEntity<ApiResponse<BoardResponse>> createBoard(
            @Valid @RequestBody BoardRequest request,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        BoardResponse response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableBoardService.createBoard(request);
        } else {
            response = secureBoardService.createBoard(request);
        }

        return ResponseEntity.ok(ApiResponse.success("게시글 작성 성공", response));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<Page<BoardResponse>>> getBoards(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "createdAt") String sort,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, sort));

        Page<BoardResponse> response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableBoardService.getBoards(pageable);
        } else {
            response = secureBoardService.getBoards(pageable);
        }

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/search")
    public ResponseEntity<ApiResponse<Page<BoardResponse>>> searchBoards(
            @RequestParam String keyword,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));

        Page<BoardResponse> response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableBoardService.searchBoards(keyword, pageable);
        } else {
            response = secureBoardService.searchBoards(keyword, pageable);
        }

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<BoardResponse>> getBoard(
            @PathVariable Long id,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        BoardResponse response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableBoardService.getBoard(id);
        } else {
            response = secureBoardService.getBoard(id);
        }

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<BoardResponse>> updateBoard(
            @PathVariable Long id,
            @Valid @RequestBody BoardRequest request,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        BoardResponse response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableBoardService.updateBoard(id, request);
        } else {
            response = secureBoardService.updateBoard(id, request);
        }

        return ResponseEntity.ok(ApiResponse.success("게시글 수정 성공", response));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteBoard(
            @PathVariable Long id,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        if ("vulnerable".equals(securityMode)) {
            vulnerableBoardService.deleteBoard(id);
        } else {
            secureBoardService.deleteBoard(id);
        }

        return ResponseEntity.ok(ApiResponse.success("게시글 삭제 성공", null));
    }

    @PostMapping("/{boardId}/comments")
    public ResponseEntity<ApiResponse<CommentResponse>> createComment(
            @PathVariable Long boardId,
            @Valid @RequestBody CommentRequest request,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        CommentResponse response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableBoardService.createComment(boardId, request);
        } else {
            response = secureBoardService.createComment(boardId, request);
        }

        return ResponseEntity.ok(ApiResponse.success("댓글 작성 성공", response));
    }

    @GetMapping("/{boardId}/comments")
    public ResponseEntity<ApiResponse<List<CommentResponse>>> getComments(
            @PathVariable Long boardId,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        List<CommentResponse> response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableBoardService.getComments(boardId);
        } else {
            response = secureBoardService.getComments(boardId);
        }

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @DeleteMapping("/comments/{commentId}")
    public ResponseEntity<ApiResponse<Void>> deleteComment(
            @PathVariable Long commentId,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        if ("vulnerable".equals(securityMode)) {
            vulnerableBoardService.deleteComment(commentId);
        } else {
            secureBoardService.deleteComment(commentId);
        }

        return ResponseEntity.ok(ApiResponse.success("댓글 삭제 성공", null));
    }
}
