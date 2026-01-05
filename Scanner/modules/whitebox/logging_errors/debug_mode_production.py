#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
운영 환경 디버그 모드 탐지
"""

import re
from pathlib import Path

DEBUG_PATTERNS = [
    # Python
    (r'DEBUG\s*=\s*True', 'Django/Flask DEBUG=True'),
    (r'app\.debug\s*=\s*True', 'Flask app.debug=True'),
    (r'app\.run\s*\([^)]*debug\s*=\s*True', 'Flask debug 모드 실행'),
    (r'FLASK_ENV\s*=\s*["\']?development["\']?', 'FLASK_ENV=development'),
    
    # Node.js
    (r'NODE_ENV\s*=\s*["\']development["\']', 'NODE_ENV=development'),
    (r'app\.set\s*\(\s*["\']env["\']\s*,\s*["\']development', 'Express development 모드'),
    (r'process\.env\.NODE_ENV\s*===?\s*["\']development', 'NODE_ENV 체크 없음'),
    
    # Java
    (r'spring\.profiles\.active\s*=\s*dev', 'Spring dev 프로파일'),
    (r'logging\.level\.root\s*=\s*DEBUG', 'Spring DEBUG 로깅'),
    (r'spring\.devtools\.restart\.enabled\s*=\s*true', 'Spring DevTools 활성화'),
    
    # PHP
    (r'display_errors\s*=\s*On', 'PHP display_errors=On'),
    (r'error_reporting\s*\(\s*E_ALL', 'PHP E_ALL 에러 표시'),
    (r'ini_set\s*\(\s*["\']display_errors["\']\s*,\s*["\']1', 'display_errors 활성화'),
    
    # ASP.NET
    (r'<compilation\s+debug\s*=\s*["\']true', 'ASP.NET debug=true'),
    (r'customErrors\s+mode\s*=\s*["\']Off', 'customErrors Off'),
]

ENV_FILE_PATTERNS = [
    (r'DEBUG\s*=\s*["\']?(?:true|1|yes)["\']?', '.env DEBUG 설정'),
    (r'FLASK_ENV\s*=\s*development', '.env FLASK_ENV'),
    (r'NODE_ENV\s*=\s*development', '.env NODE_ENV'),
    (r'ENVIRONMENT\s*=\s*development', '.env ENVIRONMENT'),
]

def scan(project_path, target_files):
    """디버그 모드 탐지"""
    findings = []
    
    for file_path in target_files:
        # 설정 파일 우선 검사
        is_config = any(name in str(file_path).lower() for name in 
                       ['settings', 'config', '.env', 'application.properties', 
                        'application.yml', 'web.config', 'appsettings.json'])
        
        if not is_config:
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            patterns = ENV_FILE_PATTERNS if file_path.name.startswith('.env') else DEBUG_PATTERNS
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '/*', '*')):
                    continue
                
                for pattern, description in patterns:
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
            'details': f'{len(findings)}개의 디버그 모드 설정 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **운영 환경에서 디버그 모드 비활성화** (필수)
```python
   # Python - 환경 변수 사용
   import os
   DEBUG = os.getenv('DEBUG', 'False') == 'True'
   
   # Node.js
   const isProduction = process.env.NODE_ENV === 'production';
   
   # Java (application.properties)
   spring.profiles.active=${SPRING_PROFILES_ACTIVE:prod}
```

2. **환경별 설정 분리**
```
   .env.development
   .env.production
   application-dev.yml
   application-prod.yml
```

3. **운영 환경 체크리스트**
   - DEBUG = False
   - 상세 에러 메시지 비활성화
   - 스택 트레이스 노출 금지
   - 소스맵 제거 (JS)

4. **CI/CD에서 자동 검증**
```bash
   # 배포 전 체크
   if grep -r "DEBUG.*True" .; then
       echo "DEBUG mode detected!"
       exit 1
   fi
```

5. **로그 레벨 조정**
   - 개발: DEBUG
   - 운영: INFO 또는 WARNING
            '''
        }
    
    return {'status': 'SAFE', 'details': '디버그 모드 설정 없음'}