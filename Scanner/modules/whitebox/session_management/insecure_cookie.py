#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
안전하지 않은 쿠키 설정 탐지
- HttpOnly, Secure, SameSite 누락
"""

import re
from pathlib import Path

# 쿠키 설정 패턴
COOKIE_SETTING_PATTERNS = [
    r'set_cookie\s*\(',
    r'setCookie\s*\(',
    r'res\.cookie\s*\(',
    r'response\.set_cookie\s*\(',
    r'Cookie\s*\(',
]

# 안전하지 않은 쿠키 패턴
INSECURE_COOKIE_PATTERNS = [
    (r'set_cookie\s*\([^)]*httponly\s*=\s*False', 'HttpOnly=False 설정'),
    (r'set_cookie\s*\([^)]*secure\s*=\s*False', 'Secure=False 설정'),
    (r'set_cookie\s*\([^)]*samesite\s*=\s*["\']?None', 'SameSite=None 설정'),
    (r'res\.cookie\s*\([^)]*\)(?!.*httpOnly)', 'HttpOnly 누락'),
    (r'res\.cookie\s*\([^)]*\)(?!.*secure)', 'Secure 누락'),
]

# 안전한 쿠키 패턴
SECURE_COOKIE_PATTERNS = [
    r'httponly\s*=\s*True',
    r'secure\s*=\s*True',
    r'samesite\s*=\s*["\'](?:Strict|Lax)',
    r'httpOnly:\s*true',
    r'secure:\s*true',
    r'sameSite:\s*["\'](?:strict|lax)',
]

def has_secure_cookie_settings(content, line_num, context_lines=5):
    """안전한 쿠키 설정 확인"""
    lines = content.split('\n')
    start = max(0, line_num - 2)
    end = min(len(lines), line_num + context_lines)
    context = '\n'.join(lines[start:end])
    
    secure_count = 0
    for pattern in SECURE_COOKIE_PATTERNS:
        if re.search(pattern, context, re.IGNORECASE):
            secure_count += 1
    
    # httpOnly, secure, sameSite 중 최소 2개 이상
    return secure_count >= 2

def scan(project_path, target_files):
    """안전하지 않은 쿠키 설정 진단"""
    findings = []
    
    for file_path in target_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                # 쿠키 설정 라인 찾기
                has_cookie_setting = any(re.search(p, line, re.IGNORECASE) 
                                        for p in COOKIE_SETTING_PATTERNS)
                
                if has_cookie_setting:
                    # 안전한 설정 확인
                    if not has_secure_cookie_settings(content, line_num):
                        try:
                            rel_path = file_path.relative_to(project_path)
                        except:
                            rel_path = file_path
                        
                        findings.append({
                            'file': str(rel_path),
                            'line': line_num,
                            'type': '안전하지 않은 쿠키 설정',
                            'snippet': line.strip()[:100]
                        })
                
                # 명시적으로 안전하지 않은 패턴 체크
                for pattern, description in INSECURE_COOKIE_PATTERNS:
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
            'details': f'{len(findings)}개의 안전하지 않은 쿠키 설정 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **필수 쿠키 보안 속성 설정**
```python
   # Python/Flask
   response.set_cookie(
       'session',
       value=session_id,
       httponly=True,
       secure=True,
       samesite='Strict'
   )
   
   # Express/Node.js
   res.cookie('session', sessionId, {
       httpOnly: true,
       secure: true,
       sameSite: 'strict',
       maxAge: 3600000
   });
   
   # Java/Spring
   Cookie cookie = new Cookie("session", sessionId);
   cookie.setHttpOnly(true);
   cookie.setSecure(true);
   cookie.setAttribute("SameSite", "Strict");
```

2. **각 속성의 역할**
   - HttpOnly: JavaScript 접근 차단 (XSS 방어)
   - Secure: HTTPS에서만 전송
   - SameSite: CSRF 방어

3. **운영 환경에서는 Secure 필수**
            '''
        }
    
    return {'status': 'SAFE', 'details': '쿠키 보안 설정이 적절함'}