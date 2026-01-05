#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
보안 헤더 누락 탐지
"""

import re
from pathlib import Path

SECURITY_HEADERS = {
    'X-Frame-Options': r'X-Frame-Options',
    'X-Content-Type-Options': r'X-Content-Type-Options',
    'X-XSS-Protection': r'X-XSS-Protection',
    'Strict-Transport-Security': r'Strict-Transport-Security',
    'Content-Security-Policy': r'Content-Security-Policy',
    'Referrer-Policy': r'Referrer-Policy',
}

def scan(project_path, target_files):
    """보안 헤더 설정 진단"""
    missing_headers = []
    found_headers = set()
    
    # 설정 파일, 미들웨어 검사
    config_files = [f for f in target_files if any(keyword in str(f).lower() 
                    for keyword in ['config', 'middleware', 'security', 'helmet', 'settings', 'header'])]
    
    for file_path in config_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for header_name, pattern in SECURITY_HEADERS.items():
                if re.search(pattern, content, re.IGNORECASE):
                    found_headers.add(header_name)
        except:
            continue
    
    # 누락된 헤더 확인
    for header_name in SECURITY_HEADERS.keys():
        if header_name not in found_headers:
            missing_headers.append(header_name)
    
    if missing_headers:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(missing_headers)}개의 보안 헤더 누락: {", ".join(missing_headers)}',
            'findings': [{'type': f'{h} 헤더 누락'} for h in missing_headers],
            'recommendation': '''
[권장 보안 대책]

1. **필수 보안 헤더 설정**
```python
   # Flask - Talisman 사용
   from flask_talisman import Talisman
   Talisman(app)
   
   # Express - Helmet 사용
   const helmet = require('helmet');
   app.use(helmet());
   
   # Django settings.py
   SECURE_BROWSER_XSS_FILTER = True
   SECURE_CONTENT_TYPE_NOSNIFF = True
   X_FRAME_OPTIONS = 'DENY'
```

2. **각 헤더 설명**
   - X-Frame-Options: DENY (클릭재킹 방지)
   - X-Content-Type-Options: nosniff (MIME 스니핑 방지)
   - X-XSS-Protection: 1; mode=block (XSS 필터)
   - Strict-Transport-Security: HTTPS 강제
   - Content-Security-Policy: XSS 방어
   - Referrer-Policy: no-referrer (정보 유출 방지)

3. **수동 설정 예시**
```python
   @app.after_request
   def set_security_headers(response):
       response.headers['X-Frame-Options'] = 'DENY'
       response.headers['X-Content-Type-Options'] = 'nosniff'
       response.headers['X-XSS-Protection'] = '1; mode=block'
       return response
```

4. **테스트**
   - https://securityheaders.com/
            '''
        }
    
    return {'status': 'SAFE', 'details': '모든 보안 헤더 설정됨'}