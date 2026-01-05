#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
.env 파일 노출 위험 탐지
"""

import re
from pathlib import Path

def scan(project_path, target_files):
    """.env 파일 노출 위험 진단"""
    findings = []
    
    # .env 파일 찾기
    env_files = [f for f in target_files if f.name.lower() in ['.env', '.env.local', '.env.production']]
    
    for env_file in env_files:
        try:
            rel_path = env_file.relative_to(project_path)
        except:
            rel_path = env_file
        
        findings.append({
            'file': str(rel_path),
            'type': '.env 파일 발견',
            'snippet': '환경 변수 파일이 저장소에 포함되어 있음'
        })
    
    # .gitignore 확인
    gitignore_path = project_path / '.gitignore'
    has_gitignore = gitignore_path.exists()
    env_ignored = False
    
    if has_gitignore:
        try:
            with open(gitignore_path, 'r', encoding='utf-8') as f:
                gitignore_content = f.read()
                if re.search(r'^\s*\.env', gitignore_content, re.MULTILINE):
                    env_ignored = True
        except:
            pass
    
    if env_files and not env_ignored:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(env_files)}개의 .env 파일이 .gitignore에 없음',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **.gitignore에 .env 추가**
```
   # .gitignore
   .env
   .env.local
   .env.*.local
   .env.production
   .env.development
   secrets.yml
   credentials.json
```

2. **.env.example 파일 제공**
```
   # .env.example (실제 값 없이 키만)
   DB_PASSWORD=
   API_KEY=
   SECRET_KEY=
```

3. **이미 커밋된 .env 파일 제거**
```bash
   git rm --cached .env
   git commit -m "Remove .env from repository"
```

4. **운영 환경에서는 시스템 환경 변수 사용**
            '''
        }
    
    if env_files and env_ignored:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(env_files)}개의 .env 파일 발견 (gitignore 설정됨)',
            'findings': findings,
            'recommendation': '.env 파일이 이미 커밋되었다면 git history에서 제거 필요'
        }
    
    return {'status': 'SAFE', 'details': '.env 파일 노출 위험 없음'}