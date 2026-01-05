#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
약한 CSP (Content Security Policy) 탐지
"""

import re
from pathlib import Path

WEAK_CSP_PATTERNS = [
    (r"script-src\s+['\"]?unsafe-inline", "script-src 'unsafe-inline' 사용"),
    (r"script-src\s+['\"]?unsafe-eval", "script-src 'unsafe-eval' 사용"),
    (r"script-src\s+\*", "script-src * (모든 소스 허용)"),
    (r"default-src\s+\*", "default-src * (모든 소스 허용)"),
    (r"object-src\s+\*", "object-src * 허용"),
]

CSP_HEADER_PATTERNS = [
    r'Content-Security-Policy',
    r'X-Content-Security-Policy',
    r'CSP',
]

def scan(project_path, target_files):
    """약한 CSP 설정 탐지"""
    findings = []
    has_csp = False
    
    # 설정 파일, 미들웨어 파일 검사
    config_files = [f for f in target_files if any(keyword in str(f).lower() 
                    for keyword in ['config', 'middleware', 'security', 'helmet', 'settings'])]
    
    for file_path in config_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # CSP 설정 존재 확인
            for pattern in CSP_HEADER_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    has_csp = True
                    break
            
            # 약한 CSP 패턴 검사
            for line_num, line in enumerate(lines, 1):
                for pattern, description in WEAK_CSP_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        try:
                            rel_path = file_path.relative_to(project_path)
                        except:
                            rel_path = file_path
                        
                        findings.append({
                            'file': str(rel_path),
                            'line': line_num,
                            'type': description,
                            'snippet': line.strip()[:100]
                        })
                        break
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 약한 CSP 설정 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **안전한 CSP 설정**
```
   Content-Security-Policy: 
     default-src 'self'; 
     script-src 'self' 'nonce-{random}'; 
     style-src 'self' 'nonce-{random}';
     object-src 'none';
```

2. **unsafe-inline, unsafe-eval 제거**

3. **Nonce 또는 Hash 사용**
```html
   <script nonce="r@nd0m">
```

4. **Report-Only 모드로 테스트 후 적용**
            '''
        }
    
    if not has_csp:
        return {
            'status': 'VULNERABLE',
            'details': 'CSP 설정이 없음',
            'findings': [],
            'recommendation': 'Content-Security-Policy 헤더를 설정하세요'
        }
    
    return {'status': 'SAFE', 'details': '안전한 CSP 설정'}