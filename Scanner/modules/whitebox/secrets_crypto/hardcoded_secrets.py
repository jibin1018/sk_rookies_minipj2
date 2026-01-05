#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
하드코딩된 비밀정보 탐지
"""

import re
from pathlib import Path

# 비밀정보 패턴
SECRET_PATTERNS = [
    # 일반 패스워드
    (r'password\s*=\s*["\']([^"\']{4,})["\']', 'PASSWORD', 'password 변수에 하드코딩'),
    (r'passwd\s*=\s*["\']([^"\']{4,})["\']', 'PASSWORD', 'passwd 변수에 하드코딩'),
    (r'pwd\s*=\s*["\']([^"\']{4,})["\']', 'PASSWORD', 'pwd 변수에 하드코딩'),
    
    # API 키
    (r'api[_-]?key\s*[=:]\s*["\']([^"\']{20,})["\']', 'API_KEY', 'API 키 하드코딩'),
    (r'apikey\s*[=:]\s*["\']([^"\']{20,})["\']', 'API_KEY', 'API 키 하드코딩'),
    (r'access[_-]?key\s*[=:]\s*["\']([^"\']{20,})["\']', 'ACCESS_KEY', 'Access 키 하드코딩'),
    (r'secret[_-]?key\s*[=:]\s*["\']([^"\']{20,})["\']', 'SECRET_KEY', 'Secret 키 하드코딩'),
    
    # AWS 인증정보
    (r'AKIA[0-9A-Z]{16}', 'AWS_ACCESS_KEY', 'AWS Access Key 하드코딩'),
    (r'aws_secret_access_key\s*=\s*["\']([A-Za-z0-9/+=]{40})["\']', 'AWS_SECRET', 'AWS Secret Key 하드코딩'),
    
    # 데이터베이스 접속 정보
    (r'(?:mysql|postgresql|mongodb)://[^:]+:([^@]+)@', 'DB_CONNECTION', 'DB 접속정보 하드코딩'),
    (r'jdbc:[^:]+://[^:]+:[^@]+@', 'JDBC_CONNECTION', 'JDBC 접속정보 하드코딩'),
    
    # Private Key
    (r'-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----', 'PRIVATE_KEY', 'Private Key 하드코딩'),
    
    # JWT 토큰
    (r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', 'JWT_TOKEN', 'JWT 토큰 하드코딩'),
    
    # GitHub Token
    (r'gh[pousr]_[A-Za-z0-9]{36}', 'GITHUB_TOKEN', 'GitHub 토큰 하드코딩'),
    
    # Slack Token
    (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}', 'SLACK_TOKEN', 'Slack 토큰 하드코딩'),
    
    # Google API Key
    (r'AIza[0-9A-Za-z\\-_]{35}', 'GOOGLE_API_KEY', 'Google API 키 하드코딩'),
]

# 오탐 방지용 제외 패턴
FALSE_POSITIVES = [
    r'example\.com',
    r'localhost',
    r'127\.0\.0\.1',
    r'your[_-]?(password|api|key)',
    r'<password>',
    r'\[password\]',
    r'placeholder',
    r'TODO|FIXME',
    r'test[_-]?password',
    r'password\s*=\s*["\'](\*+|x+|\.\.\.)["\']',
    r'password\s*=\s*["\'](pass|admin|root|changeme|12345)["\']',
    r'None|null|undefined|""',
    r'os\.getenv',
    r'process\.env',
    r'System\.getenv',
]

def is_false_positive(text, matched_value=''):
    """오탐 여부 확인"""
    for pattern in FALSE_POSITIVES:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    
    if matched_value:
        if len(matched_value) < 4:
            return True
        if matched_value.lower() in ['password', 'pass', 'admin', 'root', 'test', '1234', 'secret', 'key']:
            return True
    
    return False

def scan(project_path, target_files):
    """하드코딩된 비밀정보 진단"""
    findings = []
    
    for file_path in target_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                # 주석은 제외
                stripped = line.strip()
                if stripped.startswith(('#', '//', '--', '/*', '*')):
                    continue
                
                for pattern, cred_type, description in SECRET_PATTERNS:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        matched_text = match.group(0)
                        matched_value = match.group(1) if match.groups() else ''
                        
                        # 오탐 필터링
                        if is_false_positive(line, matched_value):
                            continue
                        
                        try:
                            rel_path = file_path.relative_to(project_path)
                        except:
                            rel_path = file_path
                        
                        # 민감정보 마스킹
                        if matched_value and len(matched_value) > 8:
                            masked_value = matched_value[:4] + '*' * (len(matched_value) - 8) + matched_value[-4:]
                        else:
                            masked_value = '****'
                        
                        findings.append({
                            'file': str(rel_path),
                            'line': line_num,
                            'type': f'{cred_type} - {description}',
                            'snippet': line.strip()[:80].replace(matched_value, masked_value) if matched_value else line.strip()[:80],
                            'severity': 'CRITICAL'
                        })
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 하드코딩된 인증정보 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **환경 변수 사용** (필수)
```python
   import os
   password = os.getenv('DB_PASSWORD')
   api_key = os.getenv('API_KEY')
```

2. **시크릿 관리 서비스 사용**
   - AWS Secrets Manager
   - HashiCorp Vault
   - Azure Key Vault

3. **.gitignore 설정**
```
   .env
   .env.local
   secrets.yml
   credentials.json
```

4. **이미 커밋된 비밀정보 제거**
```bash
   # Git history에서 제거
   git filter-branch --force --index-filter \
     "git rm --cached --ignore-unmatch secrets.txt" \
     --prune-empty --tag-name-filter cat -- --all
```

5. **비밀정보 로테이션**
   - 노출된 키는 즉시 폐기하고 재발급
            '''
        }
    
    return {'status': 'SAFE', 'details': '하드코딩된 인증정보가 발견되지 않음'}