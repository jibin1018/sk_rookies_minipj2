package com.company.portal.service;

import com.company.portal.dto.response.FileResponse;
import com.company.portal.entity.Employee;
import com.company.portal.entity.SecurityLog;
import com.company.portal.entity.Team;
import com.company.portal.entity.TeamFile;
import com.company.portal.exception.BadRequestException;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.repository.EmployeeRepository;
import com.company.portal.repository.SecurityLogRepository;
import com.company.portal.repository.TeamFileRepository;
import com.company.portal.repository.TeamRepository;
import com.company.portal.util.FileUtil;
import com.company.portal.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class FileService {

    private final TeamFileRepository teamFileRepository;
    private final EmployeeRepository employeeRepository;
    private final TeamRepository teamRepository;
    private final SecurityLogRepository securityLogRepository;
    private final FileUtil fileUtil;

    private static final List<String> DANGEROUS_EXTENSIONS = Arrays.asList(
            "exe", "bat", "cmd", "com", "pif", "scr", "vbs", "js", "jar", "jsp", "php", "asp", "aspx"
    );

    @Transactional
    public FileResponse uploadFile(Long teamId, MultipartFile file, String folderPath) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        Team team = teamRepository.findById(teamId)
                .orElseThrow(() -> new ResourceNotFoundException("팀을 찾을 수 없습니다"));

        // 팀 소속 확인 없음
        if (employee.getTeam() == null || !employee.getTeam().getId().equals(teamId)) {
            log.warn("Vulnerable 모드 - 권한 없는 파일 업로드!");
            logSecurityEvent("UNAUTHORIZED_FILE_UPLOAD",
                    "Unauthorized file upload: team=" + teamId + ", employee=" + currentEmployeeId);
        }

        // Vulnerable 모드: 파일 검증 없음!
        fileUtil.validateFile(file, false);

        String originalFilename = file.getOriginalFilename();
        String extension = fileUtil.getFileExtension(originalFilename).toLowerCase();

        // 위험한 확장자 감지
        if (DANGEROUS_EXTENSIONS.contains(extension)) {
            log.warn("Vulnerable 모드 - 위험한 파일 업로드 성공! file={}, extension={}", originalFilename, extension);
            logSecurityEvent("DANGEROUS_FILE_UPLOAD",
                    "Dangerous file uploaded: " + originalFilename + ", extension: " + extension);
        }

        String storedFilename = fileUtil.generateStoredFileName(originalFilename);

        try {
            String filePath = fileUtil.saveFile(file, storedFilename);

            TeamFile teamFile = TeamFile.builder()
                    .team(team)
                    .originalName(originalFilename)
                    .storedName(storedFilename)
                    .filePath(filePath)
                    .fileSize(file.getSize())
                    .folderPath(folderPath)
                    .uploadedBy(employee)
                    .downloadCount(0)
                    .build();

            TeamFile savedFile = teamFileRepository.save(teamFile);

            log.warn("Vulnerable 모드 - 파일 업로드 (검증 없음): team={}, file={}, extension={}",
                    teamId, savedFile.getId(), extension);

            return convertToResponse(savedFile);

        } catch (IOException e) {
            log.error("파일 저장 실패", e);
            throw new BadRequestException("파일 저장에 실패했습니다");
        }
    }

    @Transactional(readOnly = true)
    public List<FileResponse> getTeamFiles(Long teamId, String folderPath) {
        // 권한 체크 없음 - 모든 팀 파일 조회 가능!
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        if (employee.getTeam() == null || !employee.getTeam().getId().equals(teamId)) {
            log.warn("Vulnerable 모드 - 권한 없는 파일 조회!");
            logSecurityEvent("UNAUTHORIZED_FILE_VIEW",
                    "Viewing other team's files: team=" + teamId + ", employee=" + currentEmployeeId);
        }

        List<TeamFile> files;
        if (folderPath != null) {
            files = teamFileRepository.findByTeamIdAndFolderPath(teamId, folderPath);
        } else {
            files = teamFileRepository.findByTeamId(teamId);
        }

        return files.stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    @Transactional
    public Resource downloadFile(Long fileId, String requestedPath) {
        TeamFile file = teamFileRepository.findById(fileId)
                .orElseThrow(() -> new ResourceNotFoundException("파일을 찾을 수 없습니다"));

        // 권한 체크 없음
        try {
            // Vulnerable 모드: 경로 조작 가능!
            String filePath;
            if (requestedPath != null && !requestedPath.isEmpty()) {
                // 경로 조작 시도 감지
                if (requestedPath.contains("..") || requestedPath.contains("/etc") || requestedPath.contains("C:\\")) {
                    log.warn("Vulnerable 모드 - 경로 조작 시도! requested={}", requestedPath);
                    logSecurityEvent("PATH_TRAVERSAL",
                            "Path traversal attempt: requested=" + requestedPath + ", file=" + fileId);
                }
                filePath = fileUtil.getFilePathVulnerable(requestedPath);
            } else {
                filePath = file.getFilePath();
            }

            Path path = Paths.get(filePath);
            Resource resource = new UrlResource(path.toUri());

            if (!resource.exists() || !resource.isReadable()) {
                throw new ResourceNotFoundException("파일을 읽을 수 없습니다");
            }

            // 다운로드 횟수 증가
            file.setDownloadCount(file.getDownloadCount() + 1);
            teamFileRepository.save(file);

            log.warn("Vulnerable 모드 - 파일 다운로드 (경로 조작 가능): file={}, path={}", fileId, filePath);

            return resource;

        } catch (Exception e) {
            log.error("파일 다운로드 실패", e);
            throw new BadRequestException("파일 다운로드에 실패했습니다: " + e.getMessage());
        }
    }

    @Transactional
    public void deleteFile(Long fileId) {
        TeamFile file = teamFileRepository.findById(fileId)
                .orElseThrow(() -> new ResourceNotFoundException("파일을 찾을 수 없습니다"));

        // 권한 체크 없음 - 누구나 삭제 가능!
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();
        if (!file.getUploadedBy().getId().equals(currentEmployeeId)) {
            log.warn("Vulnerable 모드 - 권한 없는 파일 삭제!");
            logSecurityEvent("UNAUTHORIZED_FILE_DELETE",
                    "Unauthorized file deletion: file=" + fileId + ", employee=" + currentEmployeeId);
        }

        fileUtil.deleteFile(file.getFilePath());
        teamFileRepository.delete(file);

        log.warn("Vulnerable 모드 - 파일 삭제 (권한 체크 없음): file={}", fileId);
    }

    private void logSecurityEvent(String attackType, String details) {
        SecurityLog securityLog = SecurityLog.builder()
                .attackType(attackType)
                .securityMode("vulnerable")
                .details(details)
                .build();

        securityLogRepository.save(securityLog);
    }

    private FileResponse convertToResponse(TeamFile file) {
        return FileResponse.builder()
                .id(file.getId())
                .originalName(file.getOriginalName())
                .storedName(file.getStoredName())
                .fileSize(file.getFileSize())
                .downloadUrl("/api/files/" + file.getId())
                .build();
    }
}
