#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSRF 토큰 누락 탐지
"""

import re
from pathlib import Path

# CSRF 취약 패턴
CSRF_VULNERABLE_PATTERNS = {
    'python': [
        (r'@app\.route\s*\([^)]*methods\s*=\s*\[["\']GET["\'].*?(delete|update|create)', 'Flask GET 메소드로 중요 기능'),
        (r'@csrf_exempt', 'Django CSRF 보호 비활성화'),
    ],
    'javascript': [
        (r'app\.get\s*\([^)]*(?:delete|remove|update)', 'Express GET으로 중요 기능'),
        (r'router\.get\s*\([^)]*(?:delete|update)', 'Express Router GET으로 중요 기능'),
    ],
    'java': [
        (r'@GetMapping.*?(?:delete|update|remove)', 'Spring GET Mapping으로 중요 기능'),
    ],
}

# CSRF 보호 패턴
CSRF_PROTECTION_PATTERNS = [
    r'csrf_token',
    r'@csrf_protect',
    r'CSRFToken',
    r'X-CSRF-TOKEN',
    r'csurf',
    r'CsrfToken',
    r'_csrf',
]

def has_csrf_protection(content):
    """CSRF 보호 존재 확인"""
    for pattern in CSRF_PROTECTION_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False

def get_language(file_path):
    ext = file_path.suffix.lower()
    if ext == '.py': return 'python'
    elif ext in ['.js', '.ts']: return 'javascript'
    elif ext == '.java': return 'java'
    return None

def scan(project_path, target_files):
    """CSRF 취약점 진단"""
    findings = []
    
    for file_path in target_files:
        language = get_language(file_path)
        if not language or language not in CSRF_VULNERABLE_PATTERNS:
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # 파일 전체에서 CSRF 보호 확인
            file_has_protection = has_csrf_protection(content)
            
            for line_num, line in enumerate(lines, 1):
                for pattern, description in CSRF_VULNERABLE_PATTERNS[language]:
                    if re.search(pattern, line, re.IGNORECASE):
                        if file_has_protection:
                            continue
                        
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
            'details': f'{len(findings)}개의 CSRF 취약점 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **CSRF 토큰 사용** (필수)
```python
   # Flask
   from flask_wtf.csrf import CSRFProtect
   csrf = CSRFProtect(app)
   
   # Django (기본 활성화)
   {% csrf_token %}
   
   # Express
   const csrf = require('csurf');
   app.use(csrf({ cookie: true }));
```

2. **중요 기능은 POST 메소드 사용**

3. **Referer 헤더 검증**

4. **SameSite 쿠키 속성**
```
   Set-Cookie: sessionid=...; SameSite=Strict
```

5. **Double Submit Cookie 패턴**
            '''
        }
    
    return {'status': 'SAFE', 'details': 'CSRF 보호 확인됨'}