package com.company.portal.service.secure;

import com.company.portal.dto.response.FileResponse;
import com.company.portal.entity.Employee;
import com.company.portal.entity.Team;
import com.company.portal.entity.TeamFile;
import com.company.portal.exception.BadRequestException;
import com.company.portal.exception.ResourceNotFoundException;
import com.company.portal.exception.UnauthorizedException;
import com.company.portal.repository.EmployeeRepository;
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
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecureFileService {

    private final TeamFileRepository teamFileRepository;
    private final EmployeeRepository employeeRepository;
    private final TeamRepository teamRepository;
    private final FileUtil fileUtil;

    @Transactional
    public FileResponse uploadFile(Long teamId, MultipartFile file, String folderPath) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        Team team = teamRepository.findById(teamId)
                .orElseThrow(() -> new ResourceNotFoundException("팀을 찾을 수 없습니다"));

        // 팀 소속 확인
        if (employee.getTeam() == null || !employee.getTeam().getId().equals(teamId)) {
            throw new UnauthorizedException("해당 팀에 파일을 업로드할 권한이 없습니다");
        }

        // Secure 모드: 파일 검증
        fileUtil.validateFile(file, true);

        String originalFilename = file.getOriginalFilename();
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

            log.info("Secure 모드 - 파일 업로드 성공: team={}, file={}", teamId, savedFile.getId());

            return convertToResponse(savedFile);

        } catch (IOException e) {
            log.error("파일 저장 실패", e);
            throw new BadRequestException("파일 저장에 실패했습니다");
        }
    }

    @Transactional(readOnly = true)
    public List<FileResponse> getTeamFiles(Long teamId, String folderPath) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        // 팀 소속 확인
        if (employee.getTeam() == null || !employee.getTeam().getId().equals(teamId)) {
            throw new UnauthorizedException("해당 팀의 파일을 조회할 권한이 없습니다");
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
    public Resource downloadFile(Long fileId) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        TeamFile file = teamFileRepository.findById(fileId)
                .orElseThrow(() -> new ResourceNotFoundException("파일을 찾을 수 없습니다"));

        Employee employee = employeeRepository.findById(currentEmployeeId)
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다"));

        // 팀 소속 확인
        if (employee.getTeam() == null || !employee.getTeam().getId().equals(file.getTeam().getId())) {
            throw new UnauthorizedException("해당 파일을 다운로드할 권한이 없습니다");
        }

        try {
            // Secure 모드: 경로 정규화 및 검증
            String safePath = fileUtil.getFilePathSecure(file.getStoredName());
            Path path = Paths.get(safePath);
            Resource resource = new UrlResource(path.toUri());

            if (!resource.exists() || !resource.isReadable()) {
                throw new ResourceNotFoundException("파일을 읽을 수 없습니다");
            }

            // 다운로드 횟수 증가
            file.setDownloadCount(file.getDownloadCount() + 1);
            teamFileRepository.save(file);

            log.info("Secure 모드 - 파일 다운로드 성공: file={}", fileId);

            return resource;

        } catch (Exception e) {
            log.error("파일 다운로드 실패", e);
            throw new BadRequestException("파일 다운로드에 실패했습니다");
        }
    }

    @Transactional
    public void deleteFile(Long fileId) {
        Long currentEmployeeId = SecurityUtil.getCurrentEmployeeId();

        TeamFile file = teamFileRepository.findById(fileId)
                .orElseThrow(() -> new ResourceNotFoundException("파일을 찾을 수 없습니다"));

        // 업로드한 본인만 삭제 가능
        if (!file.getUploadedBy().getId().equals(currentEmployeeId)) {
            throw new UnauthorizedException("파일을 삭제할 권한이 없습니다");
        }

        // 실제 파일 삭제
        fileUtil.deleteFile(file.getFilePath());

        // DB에서 삭제
        teamFileRepository.delete(file);

        log.info("Secure 모드 - 파일 삭제 성공: file={}", fileId);
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
