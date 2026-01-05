#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
웹루트 파일 업로드 탐지
"""

import re
from pathlib import Path

# 위험한 업로드 경로 패턴
WEBROOT_PATTERNS = [
    (r'upload.*?["\'](?:static|public|www|htdocs|html)', '웹루트 디렉토리 업로드'),
    (r'UPLOAD_FOLDER\s*=\s*["\'](?:static|public|www)', 'UPLOAD_FOLDER가 웹루트'),
    (r'uploadDir.*?["\'](?:static|public|www)', 'uploadDir이 웹루트'),
    (r'destination.*?["\'](?:static|public|www)', 'destination이 웹루트'),
]

# 안전한 업로드 경로 패턴
SAFE_UPLOAD_PATTERNS = [
    r'upload.*?["\'](?:uploads|files|media|storage)',
    r'UPLOAD_FOLDER\s*=\s*["\'](?:uploads|media|storage)',
    r'outside.*?webroot',
    r'non-public',
]

def scan(project_path, target_files):
    """웹루트 업로드 취약점 진단"""
    findings = []
    
    for file_path in target_files:
        # 설정 파일, 업로드 핸들러 검사
        if not any(keyword in str(file_path).lower() 
                  for keyword in ['config', 'upload', 'file', 'settings']):
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//')):
                    continue
                
                # 안전한 패턴 먼저 체크
                is_safe = any(re.search(p, line, re.IGNORECASE) for p in SAFE_UPLOAD_PATTERNS)
                if is_safe:
                    continue
                
                for pattern, description in WEBROOT_PATTERNS:
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
            'details': f'{len(findings)}개의 웹루트 업로드 위험 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **웹루트 외부에 업로드** (필수)
```python
   # 나쁨
   UPLOAD_FOLDER = '/var/www/html/static/uploads'
   
   # 좋음
   UPLOAD_FOLDER = '/var/uploads'  # 웹서버가 접근 못하는 위치
```

2. **별도 다운로드 핸들러 제공**
```python
   @app.route('/download/<file_id>')
   def download_file(file_id):
       # 권한 확인
       file_path = get_file_path(file_id)
       return send_file(file_path)
```

3. **웹서버 설정으로 실행 차단**
```nginx
   # nginx
   location /uploads/ {
       # 스크립트 실행 금지
       location ~ \.(php|jsp|asp)$ {
           deny all;
       }
   }
```

4. **Content-Disposition 헤더**
```python
   return send_file(path, as_attachment=True)
```

5. **X-Content-Type-Options: nosniff**
            '''
        }
    
    return {'status': 'SAFE', 'details': '안전한 업로드 경로 설정'}