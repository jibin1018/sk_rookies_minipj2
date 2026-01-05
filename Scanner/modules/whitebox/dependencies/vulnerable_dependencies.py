#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
취약한 의존성 탐지 (간단한 버전 체크)
"""

import re
import json
from pathlib import Path

# 알려진 취약한 버전 (예시 - 실제로는 CVE DB 연동 필요)
KNOWN_VULNERABILITIES = {
    'javascript': {
        'express': {
            '<4.17.3': 'CVE-2022-24999 (qs DoS)',
        },
        'lodash': {
            '<4.17.21': 'CVE-2021-23337 (Command Injection)',
        },
        'axios': {
            '<0.21.2': 'CVE-2021-3749 (SSRF)',
        },
        'jquery': {
            '<3.5.0': 'CVE-2020-11023 (XSS)',
        },
        'moment': {
            '<2.29.2': 'CVE-2022-24785 (Path Traversal)',
        },
    },
    'python': {
        'django': {
            '<3.2.13': 'CVE-2022-28346 (SQL Injection)',
            '<4.0.4': 'CVE-2022-28347 (SQL Injection)',
        },
        'flask': {
            '<2.2.5': 'CVE-2023-30861 (Open Redirect)',
        },
        'requests': {
            '<2.31.0': 'CVE-2023-32681 (Proxy Header)',
        },
        'pillow': {
            '<9.3.0': 'CVE-2022-45198 (DoS)',
        },
        'pyyaml': {
            '<5.4': 'CVE-2020-14343 (Code Execution)',
        },
    },
    'java': {
        'spring-core': {
            '<5.3.18': 'CVE-2022-22965 (Spring4Shell RCE)',
        },
        'log4j-core': {
            '<2.17.1': 'CVE-2021-44228 (Log4Shell RCE)',
            '<2.17.0': 'CVE-2021-45105 (DoS)',
        },
        'jackson-databind': {
            '<2.13.2.1': 'CVE-2020-36518 (DoS)',
        },
        'commons-collections': {
            '<3.2.2': 'CVE-2015-6420 (RCE)',
        },
    },
}

def parse_package_json(file_path):
    """package.json 파싱"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        dependencies = {}
        for dep_type in ['dependencies', 'devDependencies']:
            if dep_type in data:
                for pkg, version in data[dep_type].items():
                    # 버전 범위 처리 (^, ~, >= 등)
                    clean_version = re.sub(r'[\^~>=<]', '', version).strip()
                    dependencies[pkg] = clean_version
        
        return dependencies
    except:
        return {}

def parse_requirements_txt(file_path):
    """requirements.txt 파싱"""
    dependencies = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    match = re.match(r'([a-zA-Z0-9_-]+)\s*(?:==|>=|<=|~=|>|<)\s*([0-9.]+)', line)
                    if match:
                        dependencies[match.group(1).lower()] = match.group(2)
    except:
        pass
    
    return dependencies

def parse_pom_xml(file_path):
    """pom.xml 파싱"""
    dependencies = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        dep_pattern = r'<dependency>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>'
        matches = re.findall(dep_pattern, content, re.DOTALL)
        
        for artifact_id, version in matches:
            dependencies[artifact_id.strip().lower()] = version.strip()
    except:
        pass
    
    return dependencies

def compare_version(current, vulnerable_pattern):
    """버전 비교"""
    if vulnerable_pattern.startswith('<'):
        threshold = vulnerable_pattern[1:].strip()
        current_parts = [int(x) for x in current.split('.') if x.isdigit()]
        threshold_parts = [int(x) for x in threshold.split('.') if x.isdigit()]
        
        for i in range(min(len(current_parts), len(threshold_parts))):
            if current_parts[i] < threshold_parts[i]:
                return True
            elif current_parts[i] > threshold_parts[i]:
                return False
        
        return len(current_parts) < len(threshold_parts)
    
    return False

def check_vulnerabilities(package_name, version, ecosystem):
    """취약점 확인"""
    if ecosystem not in KNOWN_VULNERABILITIES:
        return None
    
    vuln_db = KNOWN_VULNERABILITIES[ecosystem]
    package_name = package_name.lower()
    
    if package_name not in vuln_db:
        return None
    
    for version_pattern, cve_info in vuln_db[package_name].items():
        if compare_version(version, version_pattern):
            return cve_info
    
    return None

def scan(project_path, target_files):
    """취약한 의존성 진단"""
    findings = []
    
    dependency_files = {
        'package.json': ('javascript', parse_package_json),
        'requirements.txt': ('python', parse_requirements_txt),
        'pom.xml': ('java', parse_pom_xml),
    }
    
    for file_path in target_files:
        file_name = file_path.name
        
        if file_name in dependency_files:
            ecosystem, parser = dependency_files[file_name]
            dependencies = parser(file_path)
            
            for package, version in dependencies.items():
                vuln = check_vulnerabilities(package, version, ecosystem)
                
                if vuln:
                    try:
                        rel_path = file_path.relative_to(project_path)
                    except:
                        rel_path = file_path
                    
                    findings.append({
                        'file': str(rel_path),
                        'package': package,
                        'version': version,
                        'vulnerability': vuln,
                        'type': 'Vulnerable Dependency',
                        'snippet': f'{package}@{version} - {vuln}'
                    })
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 취약한 의존성 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **의존성 즉시 업데이트**
```bash
   # Node.js
   npm audit fix
   npm update
   
   # Python
   pip install --upgrade <package>
   pip-audit  # 취약점 스캔
   
   # Java
   mvn versions:use-latest-releases
```

2. **자동화된 취약점 스캔**
   - Snyk (https://snyk.io/)
   - Dependabot (GitHub)
   - OWASP Dependency-Check
   - npm audit / pip-audit / safety

3. **정기적인 업데이트 정책**
   - 주요 보안 취약점: 즉시 패치
   - 일반 업데이트: 월 1회
   - 분기별 전체 의존성 리뷰

4. **lockfile 사용**
   - package-lock.json (Node.js)
   - Pipfile.lock (Python)
   - pom.xml 버전 고정

5. **CI/CD 파이프라인에 통합**
```yaml
   # GitHub Actions 예시
   - name: Run security scan
     run: npm audit --audit-level=high
```
            '''
        }
    
    return {'status': 'SAFE', 'details': '알려진 취약한 의존성 없음'}