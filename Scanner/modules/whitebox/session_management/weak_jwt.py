#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
취약한 JWT 운영 탐지
- alg=none 허용
- 약한 시크릿
- 만료 시간 없음
"""

import re
from pathlib import Path

# 취약한 JWT 패턴
WEAK_JWT_PATTERNS = [
    (r'algorithm\s*[:=]\s*["\']none["\']', 'JWT algorithm=none 허용'),
    (r'verify\s*[:=]\s*false', 'JWT 서명 검증 비활성화'),
    (r'jwt\.decode\s*\([^)]*verify\s*=\s*False', 'JWT decode verify=False'),
    (r'secret\s*[:=]\s*["\'][^"\']{1,10}["\']', 'JWT 시크릿이 너무 짧음 (10자 이하)'),
    (r'jwt\.encode\s*\([^)]*\)(?!.*exp)', 'JWT 만료 시간 없음'),
]

# 하드코딩된 JWT 시크릿
HARDCODED_JWT_SECRET = [
    (r'secret\s*[:=]\s*["\'](?:secret|password|key|jwt)["\']', 'JWT 시크릿 하드코딩'),
    (r'SECRET_KEY\s*=\s*["\'][^"\']+["\']', 'SECRET_KEY 하드코딩'),
]

def scan(project_path, target_files):
    """취약한 JWT 운영 진단"""
    findings = []
    
    for file_path in target_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '/*', '*')):
                    continue
                
                # 취약한 JWT 패턴 검사
                for pattern, description in WEAK_JWT_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        try:
                            rel_path = file_path.relative_to(project_path)
                        except:
                            rel_path = file_path
                        
                        findings.append({
                            'file': str(rel_path),
                            'line': line_num,
                            'type': description,
                            'snippet': line.strip()[:100],
                            'severity': 'HIGH'
                        })
                        break
                
                # 하드코딩된 시크릿 검사
                for pattern, description in HARDCODED_JWT_SECRET:
                    if re.search(pattern, line, re.IGNORECASE):
                        try:
                            rel_path = file_path.relative_to(project_path)
                        except:
                            rel_path = file_path
                        
                        findings.append({
                            'file': str(rel_path),
                            'line': line_num,
                            'type': description,
                            'snippet': line.strip()[:100],
                            'severity': 'CRITICAL'
                        })
                        break
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 취약한 JWT 설정 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **강력한 알고리즘 사용**
```python
   # Python
   token = jwt.encode(
       payload,
       secret_key,
       algorithm='HS256'  # RS256 권장
   )
   
   # Node.js
   const token = jwt.sign(payload, secretKey, {
       algorithm: 'HS256',
       expiresIn: '1h'
   });
```

2. **반드시 만료 시간 설정**
```python
   payload = {
       'user_id': user.id,
       'exp': datetime.utcnow() + timedelta(hours=1)
   }
```

3. **환경 변수로 시크릿 관리**
```python
   SECRET_KEY = os.getenv('JWT_SECRET_KEY')
```

4. **서명 검증 필수**
```python
   payload = jwt.decode(token, secret_key, algorithms=['HS256'])
```

5. **알고리즘 화이트리스트**
```python
   jwt.decode(token, key, algorithms=['HS256', 'RS256'])
```

6. **Refresh Token 패턴 사용**
   - Access Token: 짧은 만료 시간 (15분)
   - Refresh Token: 긴 만료 시간 (7일)
            '''
        }
    
    return {'status': 'SAFE', 'details': 'JWT 설정이 안전함'}