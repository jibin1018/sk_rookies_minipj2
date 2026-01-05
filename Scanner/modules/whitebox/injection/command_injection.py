#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OS Command Injection 탐지
"""

import re
from pathlib import Path

COMMAND_INJECTION_PATTERNS = {
    'python': [
        (r'os\.system\s*\([^)]*\+', 'os.system() 문자열 연결'),
        (r'os\.system\s*\([^)]*%', 'os.system() 문자열 포매팅'),
        (r'os\.system\s*\(f["\']', 'os.system() f-string 사용'),
        (r'os\.popen\s*\([^)]*\+', 'os.popen() 문자열 연결'),
        (r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True', 'subprocess shell=True 사용'),
        (r'subprocess\.(?:call|run|Popen)\s*\([^)]*\+', 'subprocess 문자열 연결'),
        (r'eval\s*\([^)]*input\s*\(', 'eval(input()) 사용'),
        (r'exec\s*\([^)]*input\s*\(', 'exec(input()) 사용'),
        (r'__import__\s*\([^)]*input', '__import__ 동적 임포트'),
    ],
    'java': [
        (r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+', 'Runtime.exec() 문자열 연결'),
        (r'ProcessBuilder\s*\([^)]*\+', 'ProcessBuilder 문자열 연결'),
        (r'\.exec\s*\(\s*["\'][^"\']*\s*\+', 'exec 문자열 연결'),
    ],
    'php': [
        (r'exec\s*\(\s*\$', 'exec() 변수 사용'),
        (r'shell_exec\s*\(\s*\$', 'shell_exec() 변수 사용'),
        (r'system\s*\(\s*\$', 'system() 변수 사용'),
        (r'passthru\s*\(\s*\$', 'passthru() 변수 사용'),
        (r'popen\s*\(\s*\$', 'popen() 변수 사용'),
        (r'proc_open\s*\(\s*\$', 'proc_open() 변수 사용'),
        (r'`[^`]*\$', '백틱 연산자에 변수 사용'),
    ],
    'javascript': [
        (r'child_process\.exec\s*\([^)]*\+', 'child_process.exec() 문자열 연결'),
        (r'child_process\.spawn\s*\([^)]*\+', 'child_process.spawn() 문자열 연결'),
        (r'child_process\.execSync\s*\([^)]*\+', 'child_process.execSync() 문자열 연결'),
        (r'\.exec\s*\(\s*`[^`]*\$\{', 'exec() 템플릿 리터럴'),
    ],
}

SAFE_COMMAND_PATTERNS = [
    r'subprocess\.run\s*\(\s*\[',  # Array form (safe)
    r'subprocess\.Popen\s*\(\s*\[',
    r'shell\s*=\s*False',
]

def get_language(file_path):
    ext = file_path.suffix.lower()
    if ext == '.py': return 'python'
    elif ext in ['.js', '.ts', '.jsx', '.tsx']: return 'javascript'
    elif ext == '.java': return 'java'
    elif ext == '.php': return 'php'
    return None

def is_safe_command(line):
    for pattern in SAFE_COMMAND_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False

def scan(project_path, target_files):
    """OS Command Injection 취약점 진단"""
    findings = []
    
    for file_path in target_files:
        language = get_language(file_path)
        if not language or language not in COMMAND_INJECTION_PATTERNS:
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '--', '/*', '*')):
                    continue
                
                if is_safe_command(line):
                    continue
                
                for pattern, description in COMMAND_INJECTION_PATTERNS[language]:
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
            'details': f'{len(findings)}개의 OS Command Injection 취약점 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **OS 명령어 실행 함수 사용 금지** (가능하면)
   - 라이브러리 함수로 대체

2. **불가피한 경우 배열 형태 사용**
```python
   # Python - 안전
   subprocess.run(['ls', '-la', user_input], shell=False)
   
   # Node.js - 안전
   const { spawn } = require('child_process');
   spawn('ls', ['-la', userInput]);
```

3. **입력값 검증**
   - 화이트리스트 기반 검증
   - 특수문자 필터링 (;, |, &, `, $, <, >, 등)

4. **절대 shell=True 사용 금지**

5. **최소 권한으로 실행**
            '''
        }
    
    return {'status': 'SAFE', 'details': 'OS Command Injection 취약점 없음'}