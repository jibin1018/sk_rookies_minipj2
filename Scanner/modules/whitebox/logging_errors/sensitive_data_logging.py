#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
로그에 민감정보 출력 탐지
"""

import re
from pathlib import Path

# 민감정보 로깅 패턴
SENSITIVE_LOGGING_PATTERNS = [
    # 패스워드 로깅
    (r'log(?:ger)?\.(?:debug|info|warn|error)\s*\([^)]*password', '로그에 password 출력'),
    (r'console\.log\s*\([^)]*password', 'console.log에 password'),
    (r'print\s*\([^)]*password', 'print에 password'),
    (r'System\.out\.println\s*\([^)]*password', 'System.out에 password'),
    
    # 토큰/키 로깅
    (r'log(?:ger)?\.(?:debug|info)\s*\([^)]*(?:token|api_key|secret)', '로그에 토큰/키 출력'),
    (r'console\.log\s*\([^)]*(?:token|apiKey|secret)', 'console.log에 토큰'),
    
    # 카드 번호
    (r'log.*?(?:card|credit).*?number', '로그에 카드 번호'),
    
    # 주민등록번호 (한국)
    (r'log.*?(?:ssn|주민|resident)', '로그에 주민번호'),
    
    # 전체 request 객체 로깅
    (r'log.*?request\s*\)', '로그에 전체 request 객체'),
    (r'console\.log\s*\(\s*req\s*\)', 'console.log에 전체 req'),
]

def scan(project_path, target_files):
    """민감정보 로깅 진단"""
    findings = []
    
    for file_path in target_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '/*', '*')):
                    continue
                
                for pattern, description in SENSITIVE_LOGGING_PATTERNS:
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
            'details': f'{len(findings)}개의 민감정보 로깅 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **민감정보 로깅 금지** (필수)
```python
   # 나쁨
   logger.info(f"User login: {username}, password: {password}")
   
   # 좋음
   logger.info(f"User login: {username}")
```

2. **민감정보 마스킹**
```python
   def mask_sensitive(data):
       if 'password' in data:
           data['password'] = '****'
       if 'credit_card' in data:
           data['credit_card'] = data['credit_card'][:4] + '****' + data['credit_card'][-4:]
       return data
   
   logger.info(f"Request: {mask_sensitive(request_data)}")
```

3. **구조화된 로깅**
```python
   # 필요한 필드만 로깅
   logger.info("User login", extra={
       'user_id': user.id,
       'username': user.username,
       'ip': request.ip
   })
```

4. **로그 필터 설정**
```python
   class SensitiveDataFilter(logging.Filter):
       def filter(self, record):
           record.msg = re.sub(r'password=\S+', 'password=****', record.msg)
           return True
   
   logger.addFilter(SensitiveDataFilter())
```

5. **로그 검토 프로세스**
   - 정기적으로 로그 파일 검토
   - 민감정보 유출 여부 확인
            '''
        }
    
    return {'status': 'SAFE', 'details': '민감정보 로깅 없음'}