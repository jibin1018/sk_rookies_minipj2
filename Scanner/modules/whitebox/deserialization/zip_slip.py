#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zip Slip 취약점 탐지
"""

import re
from pathlib import Path

ZIP_EXTRACTION_PATTERNS = {
    'python': [
        (r'zipfile\.ZipFile.*?\.extractall\s*\(', 'zipfile extractall'),
        (r'tarfile\.open.*?\.extractall\s*\(', 'tarfile extractall'),
        (r'\.extract\s*\([^)]*\)', 'zip/tar extract'),
    ],
    'java': [
        (r'ZipInputStream', 'ZipInputStream'),
        (r'\.getNextEntry\s*\(', 'ZipEntry iteration'),
    ],
    'javascript': [
        (r'unzip\s*\(', 'Node.js unzip'),
        (r'extract-zip', 'extract-zip 라이브러리'),
    ],
}

# 안전한 검증 패턴
SAFE_EXTRACTION_PATTERNS = [
    r'startswith\s*\(',
    r'\.resolve\s*\(',
    r'os\.path\.abspath',
    r'path\.join.*?startswith',
    r'sanitize',
    r'validate.*?path',
]

def has_path_validation(content, line_num, context_lines=15):
    """경로 검증 확인"""
    lines = content.split('\n')
    start = max(0, line_num - 5)
    end = min(len(lines), line_num + context_lines)
    context = '\n'.join(lines[start:end])
    
    for pattern in SAFE_EXTRACTION_PATTERNS:
        if re.search(pattern, context, re.IGNORECASE):
            return True
    
    return False

def get_language(file_path):
    ext = file_path.suffix.lower()
    if ext == '.py': return 'python'
    elif ext in ['.js', '.ts']: return 'javascript'
    elif ext == '.java': return 'java'
    return None

def scan(project_path, target_files):
    """Zip Slip 취약점 진단"""
    findings = []
    
    for file_path in target_files:
        language = get_language(file_path)
        if not language or language not in ZIP_EXTRACTION_PATTERNS:
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '/*', '*')):
                    continue
                
                for pattern, description in ZIP_EXTRACTION_PATTERNS[language]:
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
                            'type': f'{description} - 경로 검증 누락',
                            'snippet': line.strip()[:100]
                        })
                        break
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 Zip Slip 취약점 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **압축 해제 시 경로 검증** (필수)
```python
   import zipfile
   import os
   
   extract_dir = '/safe/path'
   
   with zipfile.ZipFile(zip_file) as zf:
       for member in zf.namelist():
           # 절대 경로 계산
           member_path = os.path.join(extract_dir, member)
           target_path = os.path.abspath(member_path)
           
           # 경로 순회 공격 방지
           if not target_path.startswith(os.path.abspath(extract_dir)):
               raise Exception("Attempted Path Traversal in Zip File")
           
           zf.extract(member, extract_dir)
```

2. **../ 필터링**
```python
   if '..' in member:
       raise ValueError("Invalid path")
```

3. **심볼릭 링크 체크**
```python
   if member_info.is_symlink():
       continue  # 또는 에러
```

4. **압축 폭탄 방어**
```python
   MAX_SIZE = 100 * 1024 * 1024  # 100MB
   total_size = sum(f.file_size for f in zf.infolist())
   if total_size > MAX_SIZE:
       raise ValueError("Zip bomb detected")
```
            '''
        }
    
    return {'status': 'SAFE', 'details': 'Zip Slip 취약점 없음'}