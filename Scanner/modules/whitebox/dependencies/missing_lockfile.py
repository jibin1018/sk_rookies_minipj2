#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
의존성 고정 파일(lockfile) 누락 탐지
"""

import re
from pathlib import Path

DEPENDENCY_FILES = {
    'package.json': 'package-lock.json',
    'requirements.txt': 'Pipfile.lock',
    'pom.xml': None,  # Maven은 pom.xml 자체가 버전 고정
    'build.gradle': 'gradle.lockfile',
}

def scan(project_path, target_files):
    """lockfile 존재 여부 진단"""
    findings = []
    
    for dep_file, lock_file in DEPENDENCY_FILES.items():
        # dependency 파일 찾기
        dep_files = [f for f in target_files if f.name == dep_file]
        
        for dep_path in dep_files:
            if lock_file is None:
                continue
            
            # lockfile 존재 확인
            lock_path = dep_path.parent / lock_file
            
            if not lock_path.exists():
                try:
                    rel_path = dep_path.relative_to(project_path)
                except:
                    rel_path = dep_path
                
                findings.append({
                    'file': str(rel_path),
                    'type': f'{lock_file} 파일 누락',
                    'snippet': f'{dep_file} 있지만 {lock_file} 없음'
                })
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 lockfile 누락',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **lockfile 생성 및 커밋**
```bash
   # Node.js
   npm install  # package-lock.json 생성
   
   # Python (pipenv 사용)
   pipenv install  # Pipfile.lock 생성
   
   # Gradle
   gradle dependencies --write-locks
```

2. **lockfile의 중요성**
   - 정확한 버전 고정
   - 재현 가능한 빌드
   - 의도하지 않은 업데이트 방지
   - 보안 취약점 추적 용이

3. **.gitignore에서 제외**
```
   # 잘못된 예
   package-lock.json
   Pipfile.lock
   
   # lockfile은 반드시 커밋해야 함
```

4. **CI/CD에서 활용**
```bash
   # lockfile 기준으로 설치
   npm ci  # npm install 대신
   pipenv sync  # pipenv install 대신
```
            '''
        }
    
    return {'status': 'SAFE', 'details': 'lockfile 존재함'}