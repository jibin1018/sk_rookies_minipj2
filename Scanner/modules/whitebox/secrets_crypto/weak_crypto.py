#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
약한 암호화/해시 탐지
"""

import re
from pathlib import Path

WEAK_CRYPTO_PATTERNS = {
    'weak_hash': [
        (r'hashlib\.md5\s*\(', 'MD5 해시 사용', 'CRITICAL'),
        (r'hashlib\.sha1\s*\(', 'SHA1 해시 사용', 'HIGH'),
        (r'MessageDigest\.getInstance\s*\(\s*["\']MD5', 'Java MD5 사용', 'CRITICAL'),
        (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1', 'Java SHA1 사용', 'HIGH'),
        (r'md5\s*\(', 'PHP md5() 사용', 'CRITICAL'),
        (r'sha1\s*\(', 'PHP sha1() 사용', 'HIGH'),
        (r'crypto\.createHash\s*\(\s*["\']md5', 'Node.js MD5', 'CRITICAL'),
        (r'crypto\.createHash\s*\(\s*["\']sha1', 'Node.js SHA1', 'HIGH'),
    ],
    
    'weak_encryption': [
        (r'Cipher\.getInstance\s*\(\s*["\']DES', 'DES 암호화 (취약)', 'CRITICAL'),
        (r'Cipher\.getInstance\s*\(\s*["\']AES/ECB', 'AES ECB 모드', 'HIGH'),
        (r'createCipheriv\s*\(\s*["\']aes.*ecb', 'Node.js AES ECB', 'HIGH'),
        (r'mcrypt_encrypt\s*\([^)]*MCRYPT_DES', 'PHP DES 암호화', 'CRITICAL'),
    ],
    
    'hardcoded_iv': [
        (r'IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*\d+\s*\]', '고정 IV (제로)', 'MEDIUM'),
        (r'iv\s*=\s*["\'][0-9a-fA-F]{16,}["\']', '하드코딩된 IV', 'MEDIUM'),
        (r'iv\s*=\s*b["\'][^"\']*["\']', 'Python 하드코딩 IV', 'MEDIUM'),
    ],
}

SAFE_CRYPTO_PATTERNS = [
    r'bcrypt',
    r'scrypt',
    r'argon2',
    r'PBKDF2',
    r'hashlib\.sha256',
    r'hashlib\.sha512',
    r'AES/GCM',
    r'AES/CBC',
    r'ChaCha20',
]

def is_safe_crypto(content, line_num, context_lines=10):
    """안전한 암호화 사용 확인"""
    lines = content.split('\n')
    start = max(0, line_num - context_lines)
    end = min(len(lines), line_num + context_lines)
    context = '\n'.join(lines[start:end])
    
    for pattern in SAFE_CRYPTO_PATTERNS:
        if re.search(pattern, context, re.IGNORECASE):
            return True
    
    return False

def scan(project_path, target_files):
    """약한 암호화/해시 진단"""
    findings = []
    
    for file_path in target_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '/*', '*')):
                    continue
                
                # 모든 카테고리 검사
                for category, patterns in WEAK_CRYPTO_PATTERNS.items():
                    for pattern, description, severity in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            # 안전한 패턴 확인 (단, 체크섬 용도는 허용)
                            if 'checksum' in line.lower() or 'hash' in line.lower():
                                if category == 'weak_hash':
                                    continue
                            
                            if is_safe_crypto(content, line_num):
                                continue
                            
                            try:
                                rel_path = file_path.relative_to(project_path)
                            except:
                                rel_path = file_path
                            
                            findings.append({
                                'file': str(rel_path),
                                'line': line_num,
                                'type': f'[{category}] {description}',
                                'snippet': line.strip()[:100],
                                'severity': severity
                            })
                            break
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 약한 암호화/해시 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **비밀번호는 bcrypt/scrypt/argon2 사용** (필수)
```python
   # Python
   import bcrypt
   hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
   
   # Node.js
   const bcrypt = require('bcrypt');
   const hash = await bcrypt.hash(password, 10);
   
   # Java
   BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
   String hashed = encoder.encode(password);
```

2. **대칭키 암호화는 AES-GCM 사용**
```java
   Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
```

3. **솔트/IV는 랜덤 생성**
```python
   import os
   iv = os.urandom(16)  # 매번 랜덤 생성
   salt = os.urandom(32)
```

4. **MD5/SHA1은 체크섬 용도로만**
   - 비밀번호/인증 용도 절대 금지
   - 파일 무결성 검증은 SHA256 이상

5. **키 길이**
   - AES: 최소 256bit
   - RSA: 최소 2048bit (권장 4096bit)
            '''
        }
    
    return {'status': 'SAFE', 'details': '안전한 암호화 사용 확인'}