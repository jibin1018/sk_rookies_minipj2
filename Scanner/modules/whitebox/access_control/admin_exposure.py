#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
관리자 페이지 노출 탐지
- /admin, /manage 등 관리자 엔드포인트가 보호되지 않음
"""

import re
from pathlib import Path

# 관리자 경로 패턴
ADMIN_PATH_PATTERNS = [
    r'/admin',
    r'/manage',
    r'/console',
    r'/dashboard',
    r'/settings',
    r'/config',
    r'/system',
    r'/superuser',
]

# 관리자 보호 패턴
ADMIN_PROTECTION_PATTERNS = [
    r'@PreAuthorize.*ADMIN',
    r'@RolesAllowed.*ADMIN',
    r'hasRole.*ADMIN',
    r'requireAdmin',
    r'isAdmin',
    r'adminOnly',
    r'ROLE_ADMIN',
    r'is_superuser',
    r'is_staff',
]

def is_admin_path(path):
    """관리자 경로 확인"""
    for pattern in ADMIN_PATH_PATTERNS:
        if re.search(pattern, path, re.IGNORECASE):
            return True
    return False

def has_admin_protection(content, context):
    """관리자 보호 확인"""
    for pattern in ADMIN_PROTECTION_PATTERNS:
        if re.search(pattern, content + context, re.IGNORECASE):
            return True
    return False

def scan(project_path, target_files):
    """관리자 페이지 노출 탐지"""
    findings = []
    
    # 라우팅 파일 우선 검사
    route_files = [f for f in target_files if any(keyword in str(f).lower() 
                   for keyword in ['route', 'url', 'controller', 'api', 'view'])]
    
    for file_path in route_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                # 라우트 패턴 찾기
                route_match = re.search(r'["\']([/\w-]+)["\']', line)
                if route_match:
                    path = route_match.group(1)
                    
                    if is_admin_path(path):
                        # 주변 컨텍스트 확인
                        start = max(0, line_num - 10)
                        end = min(len(lines), line_num + 5)
                        context = '\n'.join(lines[start:end])
                        
                        if not has_admin_protection(content, context):
                            try:
                                rel_path = file_path.relative_to(project_path)
                            except:
                                rel_path = file_path
                            
                            findings.append({
                                'file': str(rel_path),
                                'line': line_num,
                                'type': '보호되지 않은 관리자 경로',
                                'path': path,
                                'snippet': line.strip()[:100]
                            })
        
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 보호되지 않은 관리자 경로 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **관리자 엔드포인트 강력한 보호**
```java
   // Spring
   @PreAuthorize("hasRole('ADMIN')")
   @GetMapping("/admin/users")
   public String adminPanel() { }
   
   // Django
   @user_passes_test(lambda u: u.is_superuser)
   def admin_view(request):
   
   // Express
   app.get('/admin', requireAdmin, (req, res) => {});
```

2. **IP 화이트리스트**
   - 관리자 페이지는 특정 IP에서만 접근

3. **Multi-Factor Authentication (MFA)**

4. **관리자 페이지 경로 변경**
   - /admin 대신 예측 불가능한 경로 사용
   - 예: /secret-mgmt-2k24

5. **별도 서브도메인 사용**
   - admin.example.com (VPN 필수)
            '''
        }
    
    return {'status': 'SAFE', 'details': '관리자 페이지가 적절히 보호됨'}