package com.company.portal.controller;

import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.FileResponse;
import com.company.portal.service.FileService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/teams/{teamId}/files")
@RequiredArgsConstructor
public class FileController {

    private final FileService fileService;

    @PostMapping
    public ResponseEntity<ApiResponse<FileResponse>> uploadFile(
            @PathVariable Long teamId,
            @RequestParam("file") MultipartFile file,
            @RequestParam(required = false) String folderPath) {

        FileResponse response = fileService.uploadFile(teamId, file, folderPath);
        return ResponseEntity.ok(ApiResponse.success("파일 업로드 성공", response));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<FileResponse>>> getTeamFiles(
            @PathVariable Long teamId,
            @RequestParam(required = false) String folderPath) {

        List<FileResponse> response = fileService.getTeamFiles(teamId, folderPath);
        return ResponseEntity.ok(ApiResponse.success(response));
    }
}

@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
@Slf4j
class FileDownloadController {

    private final FileService fileService;

    @GetMapping("/{fileId}")
    public ResponseEntity<Resource> downloadFile(
            @PathVariable Long fileId,
            @RequestParam(required = false) String path) throws UnsupportedEncodingException {

        Resource resource = fileService.downloadFile(fileId, path);

        String filename = resource.getFilename();
        String encodedFilename = URLEncoder.encode(filename, "UTF-8").replaceAll("\\+", "%20");

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + encodedFilename + "\"")
                .body(resource);
    }

    @DeleteMapping("/{fileId}")
    public ResponseEntity<ApiResponse<Void>> deleteFile(@PathVariable Long fileId) {
        fileService.deleteFile(fileId);
        return ResponseEntity.ok(ApiResponse.success("파일 삭제 성공", null));
    }
}
