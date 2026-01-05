#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTPS 강제 리다이렉트 누락 탐지
"""

import re
from pathlib import Path

HTTPS_REDIRECT_PATTERNS = [
    r'SECURE_SSL_REDIRECT',
    r'force_https',
    r'requireHTTPS',
    r'redirect.*?https',
    r'HSTS',
    r'Strict-Transport-Security',
]

def scan(project_path, target_files):
    """HTTPS 리다이렉트 설정 진단"""
    findings = []
    has_https_config = False
    
    # 설정 파일, 미들웨어 검사
    config_files = [f for f in target_files if any(keyword in str(f).lower() 
                    for keyword in ['config', 'middleware', 'settings', 'server', 'app'])]
    
    for file_path in config_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for pattern in HTTPS_REDIRECT_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    has_https_config = True
                    break
            
            if has_https_config:
                break
        except:
            continue
    
    if not has_https_config:
        return {
            'status': 'VULNERABLE',
            'details': 'HTTPS 강제 리다이렉트 설정 없음',
            'findings': [],
            'recommendation': '''
[권장 보안 대책]

1. **HTTPS 리다이렉트 설정**
```python
   # Django
   SECURE_SSL_REDIRECT = True
   
   # Flask
   from flask_talisman import Talisman
   Talisman(app, force_https=True)
   
   # Express
   app.use((req, res, next) => {
       if (req.header('x-forwarded-proto') !== 'https') {
           res.redirect(`https://${req.header('host')}${req.url}`);
       } else {
           next();
       }
   });
```

2. **HSTS 헤더 설정**
```
   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

3. **웹서버 레벨 리다이렉트**
```nginx
   # nginx
   server {
       listen 80;
       server_name example.com;
       return 301 https://$server_name$request_uri;
   }
```

4. **HSTS Preload 등록**
   - https://hstspreload.org/
            '''
        }
    
    return {'status': 'SAFE', 'details': 'HTTPS 리다이렉트 설정됨'}