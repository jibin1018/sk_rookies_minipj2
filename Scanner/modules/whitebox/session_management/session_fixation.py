#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
세션 고정 (Session Fixation) 탐지
- 로그인 시 세션 재발급 누락
"""

import re
from pathlib import Path

# 로그인 함수 패턴
LOGIN_PATTERNS = [
    r'def\s+login\s*\(',
    r'function\s+login\s*\(',
    r'async\s+function\s+login\s*\(',
    r'login\s*:\s*function\s*\(',
    r'login\s*:\s*async\s*function\s*\(',
    r'public\s+\w+\s+login\s*\(',
]

# 세션 재발급 패턴
SESSION_REGENERATE_PATTERNS = [
    r'session\.regenerate',
    r'session_regenerate_id',
    r'regenerateSession',
    r'new_session',
    r'session\.clear',
    r'session\.invalidate',
]

def has_session_regenerate(content, line_num, context_lines=30):
    """세션 재발급 로직 확인"""
    lines = content.split('\n')
    start = line_num
    end = min(len(lines), line_num + context_lines)
    context = '\n'.join(lines[start:end])
    
    for pattern in SESSION_REGENERATE_PATTERNS:
        if re.search(pattern, context, re.IGNORECASE):
            return True
    
    return False

def scan(project_path, target_files):
    """세션 고정 취약점 진단"""
    findings = []
    
    for file_path in target_files:
        # 인증 관련 파일만 검사
        if not any(keyword in str(file_path).lower() 
                  for keyword in ['auth', 'login', 'session', 'user']):
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                # 로그인 함수 찾기
                for pattern in LOGIN_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        # 세션 재발급 확인
                        if not has_session_regenerate(content, line_num):
                            try:
                                rel_path = file_path.relative_to(project_path)
                            except:
                                rel_path = file_path
                            
                            findings.append({
                                'file': str(rel_path),
                                'line': line_num,
                                'type': '로그인 시 세션 재발급 누락',
                                'snippet': line.strip()[:100]
                            })
                        break
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 세션 고정 취약점 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **로그인 성공 시 세션 재발급** (필수)
```python
   # Flask
   @app.route('/login', methods=['POST'])
   def login():
       if verify_credentials(username, password):
           session.clear()
           session.regenerate()  # 또는 새 세션 생성
           session['user_id'] = user.id
   
   # Express
   app.post('/login', (req, res) => {
       if (verifyCredentials(username, password)) {
           req.session.regenerate((err) => {
               req.session.userId = user.id;
           });
       }
   });
   
   # PHP
   session_regenerate_id(true);
   
   # Java/Spring
   request.getSession().invalidate();
   request.getSession(true);
```

2. **권한 상승 시에도 세션 재발급**

3. **로그아웃 시 세션 완전 삭제**
            '''
        }
    
    return {'status': 'SAFE', 'details': '세션 재발급 로직 확인됨'}