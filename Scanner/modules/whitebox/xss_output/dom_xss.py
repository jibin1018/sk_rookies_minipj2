#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DOM XSS 탐지
"""

import re
from pathlib import Path

DOM_XSS_PATTERNS = [
    # URL 파라미터를 DOM에 직접 삽입
    (r'location\.hash', 'location.hash 사용'),
    (r'location\.search', 'location.search 사용'),
    (r'document\.URL', 'document.URL 사용'),
    (r'document\.referrer', 'document.referrer 사용'),
    (r'window\.name', 'window.name 사용'),
    
    # Sink 함수들
    (r'\.innerHTML\s*=.*?(?:location|document\.)', 'innerHTML에 location/document 사용'),
    (r'document\.write.*?(?:location|document\.)', 'document.write에 location/document 사용'),
    (r'eval.*?(?:location|document\.)', 'eval에 location/document 사용'),
]

def scan(project_path, target_files):
    """DOM XSS 취약점 진단"""
    findings = []
    
    # JavaScript 파일만 검사
    js_files = [f for f in target_files if f.suffix.lower() in ['.js', '.jsx', '.ts', '.tsx', '.html']]
    
    for file_path in js_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('//', '/*', '*', '<!--')):
                    continue
                
                for pattern, description in DOM_XSS_PATTERNS:
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
            'details': f'{len(findings)}개의 DOM XSS 취약점 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **URL 파라미터 검증 및 인코딩**
```javascript
   // 취약
   const name = location.search.split('=')[1];
   document.getElementById('greeting').innerHTML = 'Hello ' + name;
   
   // 안전
   const params = new URLSearchParams(location.search);
   const name = params.get('name');
   document.getElementById('greeting').textContent = 'Hello ' + name;
```

2. **textContent 사용 (innerHTML 대신)**

3. **DOMPurify 사용**
```javascript
   const clean = DOMPurify.sanitize(location.hash);
```

4. **CSP 설정**
            '''
        }
    
    return {'status': 'SAFE', 'details': 'DOM XSS 취약점 없음'}