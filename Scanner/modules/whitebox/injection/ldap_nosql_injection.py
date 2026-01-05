#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LDAP/NoSQL Injection 탐지
"""

import re
from pathlib import Path

LDAP_NOSQL_PATTERNS = {
    'python': [
        # LDAP
        (r'search_s\s*\([^)]*%', 'LDAP search 문자열 포매팅'),
        (r'search_s\s*\([^)]*\+', 'LDAP search 문자열 연결'),
        (r'search_s\s*\(f["\']', 'LDAP search f-string'),
        
        # MongoDB
        (r'find\s*\(\s*\{[^}]*\$where', 'MongoDB $where 사용'),
        (r'find\s*\(\s*eval\s*\(', 'MongoDB eval() 사용'),
        (r'\.find\s*\([^)]*\+', 'MongoDB find 문자열 연결'),
    ],
    'javascript': [
        # MongoDB
        (r'\.find\s*\(\s*\{[^}]*\$where', 'MongoDB $where 사용'),
        (r'\.find\s*\(\s*req\.(?:body|query)', 'MongoDB find에 req 직접 사용'),
        (r'\.findOne\s*\(\s*req\.(?:body|query)', 'MongoDB findOne에 req 직접 사용'),
        (r'\.update\s*\(\s*req\.(?:body|query)', 'MongoDB update에 req 직접 사용'),
    ],
    'java': [
        # LDAP
        (r'search\s*\([^)]*\+', 'LDAP search 문자열 연결'),
        (r'SearchControls.*?\+', 'SearchControls 문자열 연결'),
    ],
}

def get_language(file_path):
    ext = file_path.suffix.lower()
    if ext == '.py': return 'python'
    elif ext in ['.js', '.ts', '.jsx', '.tsx']: return 'javascript'
    elif ext == '.java': return 'java'
    return None

def scan(project_path, target_files):
    """LDAP/NoSQL Injection 취약점 진단"""
    findings = []
    
    for file_path in target_files:
        language = get_language(file_path)
        if not language or language not in LDAP_NOSQL_PATTERNS:
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '/*', '*')):
                    continue
                
                for pattern, description in LDAP_NOSQL_PATTERNS[language]:
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
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 LDAP/NoSQL Injection 취약점 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **MongoDB - 쿼리 객체 구조 검증**
```javascript
   // 취약
   const user = await User.findOne(req.body);
   
   // 안전
   const user = await User.findOne({ 
       username: req.body.username 
   });
```

2. **$where 연산자 사용 금지**

3. **LDAP - 파라미터 이스케이프**
```python
   import ldap
   # LDAP 특수문자 이스케이프
   def escape_ldap(s):
       return s.replace('\\', '\\5c').replace('*', '\\2a')
```

4. **입력값 타입 검증**
```javascript
   if (typeof req.body.username !== 'string') {
       throw new Error('Invalid input');
   }
```
            '''
        }
    
    return {'status': 'SAFE', 'details': 'LDAP/NoSQL Injection 취약점 없음'}