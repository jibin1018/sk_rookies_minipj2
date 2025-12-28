package com.company.portal.util;

import com.company.portal.exception.BadRequestException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@Component
public class FileUtil {

    @Value("${file.upload-dir}")
    private String uploadDir;

    @Value("${file.allowed-extensions}")
    private String allowedExtensions;

    // 보안 모드에 따른 파일 검증
    public void validateFile(MultipartFile file, boolean isSecureMode) {
        if (file.isEmpty()) {
            throw new BadRequestException("파일이 비어있습니다");
        }

        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null) {
            throw new BadRequestException("파일 이름이 없습니다");
        }

        if (isSecureMode) {
            // Secure 모드: 엄격한 검증
            validateFileExtension(originalFilename);
            validateFileName(originalFilename);
            validateFileSize(file.getSize());
        }
        // Vulnerable 모드: 검증 없음 (취약점 시연)
    }

    private void validateFileExtension(String filename) {
        String extension = getFileExtension(filename).toLowerCase();
        List<String> allowed = Arrays.asList(allowedExtensions.split(","));

        if (!allowed.contains(extension)) {
            throw new BadRequestException("허용되지 않는 파일 형식입니다: " + extension);
        }
    }

    private void validateFileName(String filename) {
        // 경로 조작 방지
        if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
            throw new BadRequestException("잘못된 파일 이름입니다");
        }
    }

    private void validateFileSize(long size) {
        long maxSize = 10 * 1024 * 1024; // 10MB
        if (size > maxSize) {
            throw new BadRequestException("파일 크기가 너무 큽니다 (최대 10MB)");
        }
    }

    public String getFileExtension(String filename) {
        int lastIndexOf = filename.lastIndexOf(".");
        if (lastIndexOf == -1) {
            return "";
        }
        return filename.substring(lastIndexOf + 1);
    }

    public String generateStoredFileName(String originalFilename) {
        String extension = getFileExtension(originalFilename);
        String uuid = UUID.randomUUID().toString();
        return uuid + "." + extension;
    }

    public String saveFile(MultipartFile file, String storedFileName) throws IOException {
        Path uploadPath = Paths.get(uploadDir);

        // 디렉토리가 없으면 생성
        if (!Files.exists(uploadPath)) {
            Files.createDirectories(uploadPath);
        }

        Path filePath = uploadPath.resolve(storedFileName);
        Files.copy(file.getInputStream(), filePath);

        return filePath.toString();
    }

    public void deleteFile(String filePath) {
        try {
            Path path = Paths.get(filePath);
            Files.deleteIfExists(path);
        } catch (IOException e) {
            // 로그 기록
        }
    }

    // Vulnerable 모드: 경로 정규화 없음
    public String getFilePathVulnerable(String fileName) {
        return uploadDir + File.separator + fileName;
    }

    // Secure 모드: 경로 정규화 및 검증
    public String getFilePathSecure(String fileName) {
        try {
            Path basePath = Paths.get(uploadDir).toRealPath();
            Path filePath = basePath.resolve(fileName).normalize();

            // 경로 조작 방지 검증
            if (!filePath.startsWith(basePath)) {
                throw new BadRequestException("잘못된 파일 경로입니다");
            }

            return filePath.toString();
        } catch (IOException e) {
            throw new BadRequestException("파일 경로를 처리할 수 없습니다");
        }
    }
}
