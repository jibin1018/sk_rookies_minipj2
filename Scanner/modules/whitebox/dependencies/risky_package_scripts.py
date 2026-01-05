#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
위험한 패키지 스크립트 탐지
"""

import re
import json
from pathlib import Path

RISKY_SCRIPT_PATTERNS = [
    (r'postinstall.*?curl', 'postinstall에서 curl 실행'),
    (r'postinstall.*?wget', 'postinstall에서 wget 실행'),
    (r'preinstall.*?rm\s+-rf', 'preinstall에서 rm -rf'),
    (r'install.*?eval', 'install 스크립트에서 eval'),
    (r'scripts.*?sh\s+-c', 'shell 명령어 실행'),
]

def scan(project_path, target_files):
    """위험한 패키지 스크립트 진단"""
    findings = []
    
    # package.json 검사
    package_files = [f for f in target_files if f.name == 'package.json']
    
    for file_path in package_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if 'scripts' in data:
                for script_name, script_cmd in data['scripts'].items():
                    for pattern, description in RISKY_SCRIPT_PATTERNS:
                        if re.search(pattern, f'{script_name} {script_cmd}', re.IGNORECASE):
                            try:
                                rel_path = file_path.relative_to(project_path)
                            except:
                                rel_path = file_path
                            
                            findings.append({
                                'file': str(rel_path),
                                'type': description,
                                'script': script_name,
                                'snippet': script_cmd[:100]
                            })
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 위험한 패키지 스크립트 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **의심스러운 스크립트 제거**
   - postinstall에서 외부 리소스 다운로드 금지
   - 파괴적인 명령어 사용 금지

2. **패키지 검증**
```bash
   # 패키지 설치 전 검토
   npm view <package> scripts
```

3. **ignore-scripts 옵션**
```bash
   npm install --ignore-scripts
```

4. **신뢰할 수 있는 패키지만 사용**
   - 다운로드 수, 유지보수 상태 확인
   - GitHub star, 커뮤니티 평가

5. **소스 코드 검토**
   - 중요 패키지는 소스 코드 리뷰
            '''
        }
    
    return {'status': 'SAFE', 'details': '위험한 패키지 스크립트 없음'}