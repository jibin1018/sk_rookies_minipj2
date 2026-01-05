#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stored/Reflected XSS 탐지
"""

import re
from pathlib import Path

XSS_PATTERNS = {
    'python': [
        (r'\{\{\s*\w+\s*\|safe\s*\}\}', 'Django |safe 필터 사용'),
        (r'mark_safe\s*\(', 'Django mark_safe() 사용'),
        (r'Markup\s*\(', 'Flask Markup() 사용'),
        (r'autoescape\s*=\s*False', 'Jinja2 autoescape 비활성화'),
    ],
    'javascript': [
        (r'\.innerHTML\s*=\s*(?!["\'<])', 'innerHTML 변수 할당'),
        (r'\.outerHTML\s*=\s*(?!["\'<])', 'outerHTML 변수 할당'),
        (r'document\.write\s*\([^)]*\+', 'document.write 문자열 연결'),
        (r'\.html\s*\([^)]*\+', 'jQuery .html() 문자열 연결'),
        (r'eval\s*\(', 'eval() 사용'),
        (r'dangerouslySetInnerHTML', 'React dangerouslySetInnerHTML 사용'),
        (r'v-html\s*=', 'Vue v-html 사용'),
    ],
    'php': [
        (r'echo\s+\$_(?:GET|POST|REQUEST)', 'echo $_GET/$_POST 직접 출력'),
        (r'print\s+\$_(?:GET|POST)', 'print $_GET/$_POST 직접 출력'),
        (r'<\?=\s*\$_(?:GET|POST)', '<?= $_GET/$_POST 직접 출력'),
    ],
    'java': [
        (r'<%=\s*request\.getParameter', 'JSP <%= request.getParameter 직접 출력'),
        (r'out\.print.*?request\.getParameter', 'out.print request.getParameter'),
    ],
}

SAFE_XSS_PATTERNS = [
    r'escape\s*\(',
    r'escapeHtml',
    r'htmlspecialchars',
    r'sanitize',
    r'textContent\s*=',
    r'innerText\s*=',
    r'DOMPurify',
]

def get_language(file_path):
    ext = file_path.suffix.lower()
    name = file_path.name.lower()
    
    if ext == '.py' or '.html' in name: return 'python'
    elif ext in ['.js', '.jsx', '.ts', '.tsx', '.vue', '.html']: return 'javascript'
    elif ext in ['.jsp', '.java']: return 'java'
    elif ext == '.php': return 'php'
    return None

def is_safe_xss(line):
    for pattern in SAFE_XSS_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False

def scan(project_path, target_files):
    """XSS 취약점 진단"""
    findings = []
    
    for file_path in target_files:
        language = get_language(file_path)
        if not language or language not in XSS_PATTERNS:
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '<!--', '/*', '*')):
                    continue
                
                if is_safe_xss(line):
                    continue
                
                for pattern, description in XSS_PATTERNS[language]:
                    if re.search(pattern, line, re.IGNORECASE):
                        try:
                            rel_path = file_path.relative_to(project_path)
                        except:
                            rel_path = file_path
                        
                        findings.append({
                            'file': str(rel_path),
                            'line': line_num,
                            'type': description,
                            'snippet': line.strip()[:100],
                            'severity': 'HIGH'
                        })
                        break
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 XSS 취약점 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **출력 시 이스케이프 처리** (필수)
```python
   # Python
   from html import escape
   safe_output = escape(user_input)
   
   # JavaScript
   element.textContent = userInput;  // innerHTML 대신
   
   # PHP
   echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
```

2. **프레임워크 보안 기능 활용**
   - Django: 기본 자동 이스케이프 (|safe 사용 자제)
   - React: JSX 자동 이스케이프

3. **Content Security Policy (CSP) 설정**

4. **DOMPurify 같은 라이브러리 사용**
```javascript
   const clean = DOMPurify.sanitize(dirty);
```
            '''
        }
    
    return {'status': 'SAFE', 'details': 'XSS 취약점 없음'}