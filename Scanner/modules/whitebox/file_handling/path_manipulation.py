#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
파일명 경로 조작 탐지
"""

import re
from pathlib import Path

# 파일명 신뢰 패턴 (위험)
FILENAME_TRUST_PATTERNS = [
    (r'\.save\s*\([^)]*filename\s*=\s*(?!secure)', 'save()에 파일명 직접 사용'),
    (r'open\s*\([^)]*\+\s*filename', 'open()에 파일명 직접 연결'),
    (r'os\.path\.join\s*\([^)]*filename\s*\)', 'path.join에 검증 없는 파일명'),
    (r'File\s*\([^)]*fileName', 'Java File에 파일명 직접 사용'),
    (r'move_uploaded_file\s*\([^)]*\$_FILES.*?name', 'PHP 파일명 직접 사용'),
]

# 안전한 파일명 처리 패턴
SAFE_FILENAME_PATTERNS = [
    r'secure_filename',
    r'sanitize',
    r'basename',
    r'uuid',
    r'randomFilename',
    r'replaceAll',
    r'filter',
]

def has_safe_filename_handling(content, line_num, context_lines=10):
    """안전한 파일명 처리 확인"""
    lines = content.split('\n')
    start = max(0, line_num - context_lines)
    end = min(len(lines), line_num + context_lines)
    context = '\n'.join(lines[start:end])
    
    for pattern in SAFE_FILENAME_PATTERNS:
        if re.search(pattern, context, re.IGNORECASE):
            return True
    
    return False

def scan(project_path, target_files):
    """파일명 경로 조작 취약점 진단"""
    findings = []
    
    for file_path in target_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//')):
                    continue
                
                for pattern, description in FILENAME_TRUST_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        # 안전한 처리 확인
                        if has_safe_filename_handling(content, line_num):
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
            'details': f'{len(findings)}개의 파일명 경로 조작 위험 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **파일명 검증 및 정제** (필수)
```python
   from werkzeug.utils import secure_filename
   
   filename = secure_filename(user_uploaded_filename)
```

2. **UUID로 파일명 생성**
```python
   import uuid
   
   extension = original_filename.rsplit('.', 1)[1].lower()
   new_filename = f"{uuid.uuid4()}.{extension}"
```

3. **경로 순회 문자 제거**
```python
   filename = filename.replace('..', '').replace('/', '').replace('\\', '')
```

4. **basename만 사용**
```python
   import os
   filename = os.path.basename(user_input)
```

5. **절대 경로 검증**
```python
   final_path = os.path.abspath(os.path.join(upload_dir, filename))
   if not final_path.startswith(upload_dir):
       raise ValueError("Invalid path")
```
            '''
        }
    
    return {'status': 'SAFE', 'details': '파일명 처리가 안전함'}