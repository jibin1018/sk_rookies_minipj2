#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
안전하지 않은 역직렬화 탐지
"""

import re
from pathlib import Path

UNSAFE_DESERIALIZATION_PATTERNS = {
    'python': [
        (r'pickle\.loads?\s*\(', 'pickle.load/loads 사용', 'CRITICAL'),
        (r'yaml\.load\s*\([^)]*\)(?!.*Loader=yaml\.SafeLoader)', 'YAML unsafe load', 'CRITICAL'),
        (r'marshal\.loads?\s*\(', 'marshal.load 사용', 'HIGH'),
        (r'shelve\.open\s*\(', 'shelve 사용', 'MEDIUM'),
    ],
    'java': [
        (r'ObjectInputStream', 'Java ObjectInputStream', 'CRITICAL'),
        (r'readObject\s*\(\s*\)', 'readObject() 호출', 'CRITICAL'),
        (r'XMLDecoder', 'XMLDecoder 사용', 'HIGH'),
        (r'XStream', 'XStream 사용', 'MEDIUM'),
    ],
    'php': [
        (r'unserialize\s*\(', 'PHP unserialize', 'CRITICAL'),
    ],
    'javascript': [
        (r'JSON\.parse\s*\([^)]*\)(?!.*try)', 'JSON.parse (에러 처리 없음)', 'MEDIUM'),
        (r'eval\s*\(.*?JSON', 'eval + JSON', 'CRITICAL'),
    ],
}

def get_language(file_path):
    ext = file_path.suffix.lower()
    if ext == '.py': return 'python'
    elif ext in ['.js', '.ts']: return 'javascript'
    elif ext == '.java': return 'java'
    elif ext == '.php': return 'php'
    return None

def scan(project_path, target_files):
    """안전하지 않은 역직렬화 진단"""
    findings = []
    
    for file_path in target_files:
        language = get_language(file_path)
        if not language or language not in UNSAFE_DESERIALIZATION_PATTERNS:
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '/*', '*')):
                    continue
                
                for pattern, description, severity in UNSAFE_DESERIALIZATION_PATTERNS[language]:
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
                            'severity': severity
                        })
                        break
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 안전하지 않은 역직렬화 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **안전한 대안 사용**
```python
   # Python - pickle 대신 JSON
   import json
   data = json.loads(user_input)
   
   # YAML - SafeLoader 사용
   import yaml
   data = yaml.load(input, Loader=yaml.SafeLoader)
```

2. **서명 검증**
```python
   import hmac
   import hashlib
   
   # 직렬화 시
   signature = hmac.new(secret_key, serialized_data, hashlib.sha256).hexdigest()
   
   # 역직렬화 시
   if not hmac.compare_digest(signature, received_signature):
       raise ValueError("Invalid signature")
```

3. **Java - 화이트리스트 방식**
```java
   ValidatingObjectInputStream in = new ValidatingObjectInputStream(inputStream);
   in.accept(MyAllowedClass.class);
   Object obj = in.readObject();
```

4. **신뢰할 수 없는 데이터 역직렬화 금지**

5. **JSON 같은 데이터 형식 사용**
            '''
        }
    
    return {'status': 'SAFE', 'details': '안전하지 않은 역직렬화 없음'}