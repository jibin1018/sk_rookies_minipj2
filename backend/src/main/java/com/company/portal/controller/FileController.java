package com.company.portal.controller;

import com.company.portal.dto.response.ApiResponse;
import com.company.portal.dto.response.FileResponse;
import com.company.portal.service.secure.SecureFileService;
import com.company.portal.service.vulnerable.VulnerableFileService;
import jakarta.servlet.http.HttpServletRequest;
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

    private final SecureFileService secureFileService;
    private final VulnerableFileService vulnerableFileService;

    @PostMapping
    public ResponseEntity<ApiResponse<FileResponse>> uploadFile(
            @PathVariable Long teamId,
            @RequestParam("file") MultipartFile file,
            @RequestParam(required = false) String folderPath,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        FileResponse response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableFileService.uploadFile(teamId, file, folderPath);
        } else {
            response = secureFileService.uploadFile(teamId, file, folderPath);
        }

        return ResponseEntity.ok(ApiResponse.success("파일 업로드 성공", response));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<FileResponse>>> getTeamFiles(
            @PathVariable Long teamId,
            @RequestParam(required = false) String folderPath,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        List<FileResponse> response;
        if ("vulnerable".equals(securityMode)) {
            response = vulnerableFileService.getTeamFiles(teamId, folderPath);
        } else {
            response = secureFileService.getTeamFiles(teamId, folderPath);
        }

        return ResponseEntity.ok(ApiResponse.success(response));
    }
}

@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
@Slf4j
class FileDownloadController {

    private final SecureFileService secureFileService;
    private final VulnerableFileService vulnerableFileService;

    @GetMapping("/{fileId}")
    public ResponseEntity<Resource> downloadFile(
            @PathVariable Long fileId,
            @RequestParam(required = false) String path,
            HttpServletRequest httpRequest) throws UnsupportedEncodingException {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        Resource resource;
        if ("vulnerable".equals(securityMode)) {
            resource = vulnerableFileService.downloadFile(fileId, path);
        } else {
            resource = secureFileService.downloadFile(fileId);
        }

        String filename = resource.getFilename();
        String encodedFilename = URLEncoder.encode(filename, "UTF-8").replaceAll("\\+", "%20");

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + encodedFilename + "\"")
                .body(resource);
    }

    @DeleteMapping("/{fileId}")
    public ResponseEntity<ApiResponse<Void>> deleteFile(
            @PathVariable Long fileId,
            HttpServletRequest httpRequest) {

        String securityMode = (String) httpRequest.getAttribute("securityMode");

        if ("vulnerable".equals(securityMode)) {
            vulnerableFileService.deleteFile(fileId);
        } else {
            secureFileService.deleteFile(fileId);
        }

        return ResponseEntity.ok(ApiResponse.success("파일 삭제 성공", null));
    }
}
