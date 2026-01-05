#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Template Injection 탐지 (SSTI - Server-Side Template Injection)
"""

import re
from pathlib import Path

TEMPLATE_INJECTION_PATTERNS = {
    'python': [
        # Jinja2
        (r'render_template_string\s*\([^)]*\+', 'Jinja2 render_template_string 문자열 연결'),
        (r'render_template_string\s*\(f["\']', 'Jinja2 render_template_string f-string'),
        (r'Template\s*\([^)]*(?:request|input)', 'Jinja2 Template에 사용자 입력'),
        
        # Django
        (r'Template\s*\([^)]*(?:request|input)', 'Django Template에 사용자 입력'),
    ],
    'javascript': [
        # Handlebars, Pug, EJS
        (r'compile\s*\([^)]*req\.', 'Template compile에 req 사용'),
        (r'render\s*\([^)]*req\.(?:body|query)', 'Template render에 req 사용'),
        (r'\.compile\s*\(\s*`[^`]*\$\{', 'Template compile 템플릿 리터럴'),
    ],
    'java': [
        (r'new\s+Template\s*\([^)]*request', 'Template에 request 파라미터'),
        (r'\.process\s*\([^)]*request', 'Template process에 request'),
    ],
}

def get_language(file_path):
    ext = file_path.suffix.lower()
    if ext == '.py': return 'python'
    elif ext in ['.js', '.ts', '.jsx', '.tsx']: return 'javascript'
    elif ext == '.java': return 'java'
    return None

def scan(project_path, target_files):
    """Template Injection 취약점 진단"""
    findings = []
    
    for file_path in target_files:
        language = get_language(file_path)
        if not language or language not in TEMPLATE_INJECTION_PATTERNS:
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '/*', '*')):
                    continue
                
                for pattern, description in TEMPLATE_INJECTION_PATTERNS[language]:
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
            'details': f'{len(findings)}개의 Template Injection 취약점 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **절대 사용자 입력을 템플릿으로 사용 금지**
```python
   # 취약
   template = render_template_string(user_input)
   
   # 안전
   template = render_template('template.html', data=user_input)
```

2. **샌드박스 환경 사용**
```python
   from jinja2.sandbox import SandboxedEnvironment
   env = SandboxedEnvironment()
```

3. **템플릿 파일은 정적으로 관리**

4. **사용자 입력은 데이터로만 전달**
            '''
        }
    
    return {'status': 'SAFE', 'details': 'Template Injection 취약점 없음'}