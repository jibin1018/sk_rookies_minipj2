#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Path Traversal 탐지
"""

import re
from pathlib import Path

PATH_TRAVERSAL_PATTERNS = {
    'python': [
        (r'open\s*\([^)]*(?:request|req)\.\w+', 'open()에 request 파라미터 사용'),
        (r'open\s*\([^)]*\+\s*[^)]*\)', 'open() 경로 문자열 연결'),
        (r'Path\s*\([^)]*(?:request|req)', 'Path()에 request 파라미터'),
        (r'send_file\s*\([^)]*(?:request|req)', 'send_file()에 request 파라미터'),
        (r'send_from_directory\s*\([^)]*(?:request|req)', 'send_from_directory()에 request 사용'),
        (r'\.read\s*\([^)]*(?:request|req)', 'read()에 request 파라미터'),
    ],
    'java': [
        (r'new\s+File\s*\([^)]*request\.getParameter', 'File 객체에 request 파라미터'),
        (r'Files\.read\s*\([^)]*request', 'Files.read에 request 사용'),
        (r'Paths\.get\s*\([^)]*request', 'Paths.get에 request 사용'),
        (r'FileInputStream\s*\([^)]*request', 'FileInputStream에 request'),
    ],
    'php': [
        (r'fopen\s*\(\s*\$_(?:GET|POST)', 'fopen()에 $_GET/$_POST 사용'),
        (r'file_get_contents\s*\(\s*\$_(?:GET|POST)', 'file_get_contents()에 $_GET/$_POST'),
        (r'include\s*\(\s*\$_(?:GET|POST)', 'include()에 $_GET/$_POST'),
        (r'require\s*\(\s*\$_(?:GET|POST)', 'require()에 $_GET/$_POST'),
        (r'readfile\s*\(\s*\$_(?:GET|POST)', 'readfile()에 $_GET/$_POST'),
    ],
    'javascript': [
        (r'fs\.readFile\s*\([^)]*req\.(?:query|params|body)', 'fs.readFile에 req 파라미터'),
        (r'fs\.createReadStream\s*\([^)]*req\.', 'fs.createReadStream에 req 사용'),
        (r'fs\.readFileSync\s*\([^)]*req\.', 'fs.readFileSync에 req 사용'),
        (r'path\.join\s*\([^)]*req\.', 'path.join에 req 파라미터'),
    ],
}

SAFE_PATH_PATTERNS = [
    r'os\.path\.abspath',
    r'os\.path\.realpath',
    r'\.resolve\s*\(',
    r'startswith\s*\(',
    r'\.\..*?replace\s*\(',
    r'path\.join.*?BASE_DIR',
    r'safe_join',
    r'normalize',
]

def has_path_validation(content, line_num, context_lines=15):
    """경로 검증 로직 존재 확인"""
    lines = content.split('\n')
    start = max(0, line_num - 5)
    end = min(len(lines), line_num + context_lines)
    context = '\n'.join(lines[start:end])
    
    for pattern in SAFE_PATH_PATTERNS:
        if re.search(pattern, context, re.IGNORECASE):
            return True
    
    return False

def get_language(file_path):
    ext = file_path.suffix.lower()
    if ext == '.py': return 'python'
    elif ext in ['.js', '.ts', '.jsx', '.tsx']: return 'javascript'
    elif ext == '.java': return 'java'
    elif ext == '.php': return 'php'
    return None

def scan(project_path, target_files):
    """Path Traversal 취약점 진단"""
    findings = []
    
    for file_path in target_files:
        language = get_language(file_path)
        if not language or language not in PATH_TRAVERSAL_PATTERNS:
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '/*', '*')):
                    continue
                
                for pattern, description in PATH_TRAVERSAL_PATTERNS[language]:
                    if re.search(pattern, line, re.IGNORECASE):
                        # 경로 검증 확인
                        if has_path_validation(content, line_num):
                            continue
                        
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
            'details': f'{len(findings)}개의 Path Traversal 취약점 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **절대 경로 검증** (필수)
```python
   import os
   base_dir = '/var/www/uploads'
   user_path = os.path.join(base_dir, user_input)
   real_path = os.path.realpath(user_path)
   
   if not real_path.startswith(base_dir):
       raise ValueError("Invalid path")
```

2. **../ 필터링**
```python
   filename = filename.replace('..', '')
```

3. **화이트리스트 기반 검증**
   - 허용된 파일만 접근

4. **파일명만 받고 경로는 서버에서 결정**
```python
   # 안전
   filepath = os.path.join(UPLOAD_DIR, secure_filename(user_filename))
```

5. **chroot jail 사용** (고급)
            '''
        }
    
    return {'status': 'SAFE', 'details': 'Path Traversal 취약점 없음'}