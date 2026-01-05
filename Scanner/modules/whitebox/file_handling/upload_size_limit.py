#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
파일 업로드 크기 제한 누락 탐지
"""

import re
from pathlib import Path

# 크기 제한 패턴
SIZE_LIMIT_PATTERNS = [
    r'MAX_CONTENT_LENGTH',
    r'max_file_size',
    r'maxFileSize',
    r'file_size_limit',
    r'limits.*?fileSize',
    r'multipart.*?limits',
    r'Content-Length',
]

def scan(project_path, target_files):
    """파일 업로드 크기 제한 진단"""
    findings = []
    has_size_limit = False
    
    # 설정 파일 검사
    config_files = [f for f in target_files if any(keyword in str(f).lower() 
                    for keyword in ['config', 'settings', 'app', 'server'])]
    
    for file_path in config_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for pattern in SIZE_LIMIT_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    has_size_limit = True
                    break
            
            if has_size_limit:
                break
        except:
            continue
    
    # 업로드 핸들러에서 크기 체크 확인
    upload_files = [f for f in target_files if 'upload' in str(f).lower()]
    
    for file_path in upload_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                # 파일 업로드 처리 라인 찾기
                if re.search(r'(?:save|upload|write).*?file', line, re.IGNORECASE):
                    # 주변에 크기 체크 있는지 확인
                    start = max(0, line_num - 10)
                    end = min(len(lines), line_num + 5)
                    context = '\n'.join(lines[start:end])
                    
                    has_local_check = any(re.search(p, context, re.IGNORECASE) 
                                         for p in SIZE_LIMIT_PATTERNS)
                    
                    if not has_local_check and not has_size_limit:
                        try:
                            rel_path = file_path.relative_to(project_path)
                        except:
                            rel_path = file_path
                        
                        findings.append({
                            'file': str(rel_path),
                            'line': line_num,
                            'type': '파일 크기 제한 없음',
                            'snippet': line.strip()[:100]
                        })
        except:
            continue
    
    if not has_size_limit:
        return {
            'status': 'VULNERABLE',
            'details': '파일 업로드 크기 제한이 설정되지 않음',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **전역 크기 제한 설정**
```python
   # Flask
   app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
   
   # Express
   app.use(express.json({ limit: '10mb' }));
   app.use(express.urlencoded({ limit: '10mb', extended: true }));
   
   # Django
   DATA_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB
```

2. **개별 파일 크기 검증**
```python
   MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
   
   if file.size > MAX_FILE_SIZE:
       raise ValueError('File too large')
```

3. **압축 폭탄 방지**
```python
   # ZIP 파일 압축 해제 시
   MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024  # 100MB
   
   total_size = 0
   with zipfile.ZipFile(file) as zf:
       for info in zf.infolist():
           total_size += info.file_size
           if total_size > MAX_UNCOMPRESSED_SIZE:
               raise ValueError('Zip bomb detected')
```

4. **타임아웃 설정**
```python
   # 업로드 타임아웃
   request_timeout = 30  # 30초
```
            '''
        }
    
    return {'status': 'SAFE', 'details': '파일 업로드 크기 제한 설정됨'}