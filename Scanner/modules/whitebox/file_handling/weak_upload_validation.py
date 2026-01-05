#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
파일 업로드 검증 취약점 탐지
"""

import re
from pathlib import Path

FILE_UPLOAD_PATTERNS = {
    'python': [
        (r'\.save\s*\([^)]*\)', '파일 저장 (검증 필요)'),
        (r'open\s*\([^)]*["\']wb["\']', '바이너리 파일 쓰기'),
        (r'request\.files', 'Flask 파일 업로드'),
        (r'request\.FILES', 'Django 파일 업로드'),
    ],
    'java': [
        (r'MultipartFile', 'Spring 파일 업로드'),
        (r'FileOutputStream', '파일 출력 스트림'),
        (r'\.transferTo\s*\(', '파일 전송'),
    ],
    'php': [
        (r'\$_FILES', 'PHP 파일 업로드'),
        (r'move_uploaded_file', '업로드 파일 이동'),
    ],
    'javascript': [
        (r'multer\s*\(', 'Node.js multer 파일 업로드'),
        (r'formidable', 'Node.js formidable'),
        (r'busboy', 'Node.js busboy'),
    ],
}

# 파일 검증 패턴 (안전)
VALIDATION_PATTERNS = [
    r'ALLOWED_EXTENSIONS',
    r'allowed_extensions',
    r'allowedExtensions',
    r'whitelist',
    r'\.endswith\s*\(',
    r'in\s+\[.*?\.jpg.*?\.png',
    r'content_type',
    r'mimetype',
    r'contentType',
    r'fileFilter',
    r'accept\s*:',
    r'MIME',
]

def has_validation(content, line_num, context_lines=15):
    """주변 코드에서 검증 로직 존재 확인"""
    lines = content.split('\n')
    start = max(0, line_num - context_lines)
    end = min(len(lines), line_num + context_lines)
    context = '\n'.join(lines[start:end])
    
    for pattern in VALIDATION_PATTERNS:
        if re.search(pattern, context, re.IGNORECASE):
            return True
    return False

def get_language(file_path):
    ext = file_path.suffix.lower()
    if ext == '.py': return 'python'
    elif ext in ['.js', '.ts']: return 'javascript'
    elif ext == '.java': return 'java'
    elif ext == '.php': return 'php'
    return None

def scan(project_path, target_files):
    """파일 업로드 검증 취약점 진단"""
    findings = []
    
    for file_path in target_files:
        language = get_language(file_path)
        if not language or language not in FILE_UPLOAD_PATTERNS:
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//')):
                    continue
                
                for pattern, description in FILE_UPLOAD_PATTERNS[language]:
                    if re.search(pattern, line, re.IGNORECASE):
                        # 검증 로직 확인
                        if has_validation(content, line_num):
                            continue
                        
                        try:
                            rel_path = file_path.relative_to(project_path)
                        except:
                            rel_path = file_path
                        
                        findings.append({
                            'file': str(rel_path),
                            'line': line_num,
                            'type': f'{description} - 검증 누락 의심',
                            'snippet': line.strip()[:100]
                        })
                        break
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 파일 업로드 검증 누락 의심',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **파일 확장자 화이트리스트 검증** (필수)
```python
   ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
   
   def allowed_file(filename):
       return '.' in filename and \
              filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
```

2. **MIME 타입 검증**
```python
   import magic
   
   mime = magic.from_buffer(file.read(1024), mime=True)
   if mime not in ['image/jpeg', 'image/png']:
       raise ValueError('Invalid file type')
```

3. **파일 크기 제한**
```python
   MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
   
   if len(file.read()) > MAX_FILE_SIZE:
       raise ValueError('File too large')
```

4. **파일명 랜덤화**
```python
   import uuid
   filename = f"{uuid.uuid4()}.{extension}"
```

5. **매직 바이트 검증**
```python
   # JPEG: FF D8 FF
   # PNG: 89 50 4E 47
```

6. **업로드 디렉토리 실행 권한 제거**
            '''
        }
    
    return {'status': 'SAFE', 'details': '파일 업로드 검증 로직 확인됨'}