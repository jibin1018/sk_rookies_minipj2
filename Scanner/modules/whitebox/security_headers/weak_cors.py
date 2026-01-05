#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
약한 CORS 설정 탐지
"""

import re
from pathlib import Path

WEAK_CORS_PATTERNS = [
    (r'Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']?\*', 'CORS: Allow-Origin *'),
    (r'CORS.*?origins?\s*=\s*\[?\s*["\']?\*', 'CORS origins=*'),
    (r'cors\s*\(\s*\)', 'CORS 기본 설정 (모든 도메인 허용)'),
    (r'Access-Control-Allow-Credentials["\']?\s*[:=]\s*["\']?true.*?Origin.*?\*', 'CORS: Credentials + Origin *'),
]

SAFE_CORS_PATTERNS = [
    r'origins?\s*=\s*\[.*?https?://.*?\]',
    r'whitelist',
    r'allowedOrigins',
]

def scan(project_path, target_files):
    """CORS 설정 진단"""
    findings = []
    
    for file_path in target_files:
        # 설정 파일, API 파일 검사
        if not any(keyword in str(file_path).lower() 
                  for keyword in ['config', 'cors', 'api', 'middleware', 'server']):
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                # 안전한 패턴 먼저 체크
                is_safe = any(re.search(p, line, re.IGNORECASE) for p in SAFE_CORS_PATTERNS)
                if is_safe:
                    continue
                
                for pattern, description in WEAK_CORS_PATTERNS:
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
            'details': f'{len(findings)}개의 약한 CORS 설정 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **도메인 화이트리스트 사용** (필수)
```python
   # Flask-CORS
   from flask_cors import CORS
   CORS(app, origins=[
       'https://example.com',
       'https://app.example.com'
   ])
   
   # Express
   const cors = require('cors');
   const corsOptions = {
       origin: ['https://example.com', 'https://app.example.com'],
       credentials: true
   };
   app.use(cors(corsOptions));
   
   # Django
   CORS_ALLOWED_ORIGINS = [
       "https://example.com",
       "https://app.example.com",
   ]
```

2. **동적 검증**
```javascript
   const allowedOrigins = ['https://example.com'];
   
   app.use(cors({
       origin: function(origin, callback) {
           if (!origin || allowedOrigins.indexOf(origin) !== -1) {
               callback(null, true);
           } else {
               callback(new Error('Not allowed by CORS'));
           }
       },
       credentials: true
   }));
```

3. **절대 사용 금지 조합**
```
   Access-Control-Allow-Origin: *
   Access-Control-Allow-Credentials: true
```
   - 이 조합은 모든 도메인에서 인증된 요청 가능 (매우 위험)

4. **필요한 메소드만 허용**
```python
   CORS(app, 
       origins=['https://example.com'],
       methods=['GET', 'POST'],
       allow_headers=['Content-Type']
   )
```
            '''
        }
    
    return {'status': 'SAFE', 'details': 'CORS 설정이 안전함'}