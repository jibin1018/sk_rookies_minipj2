package com.company.portal.util;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Component
public class HashUtil {

    // 익명 건의함용 해시 생성
    public String generateAnonymousId(Long employeeId, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String input = employeeId + salt;
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("해시 생성 실패", e);
        }
    }
}
