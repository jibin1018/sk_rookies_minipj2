#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
권한 체크 누락 탐지
- 라우트-핸들러 매핑에서 인증/인가 미들웨어 누락
- Spring @PreAuthorize/@Secured 누락
- Express 미들웨어 누락
"""

import re
from pathlib import Path

# 프레임워크별 라우트 패턴
ROUTE_PATTERNS = {
    'spring': [
        (r'@(?:Get|Post|Put|Delete|Patch)Mapping\s*\([^)]*["\']([^"\']+)', 'Spring Mapping'),
        (r'@RequestMapping\s*\([^)]*value\s*=\s*["\']([^"\']+)', 'Spring RequestMapping'),
    ],
    'express': [
        (r'app\.(?:get|post|put|delete|patch)\s*\(["\']([^"\']+)', 'Express Route'),
        (r'router\.(?:get|post|put|delete|patch)\s*\(["\']([^"\']+)', 'Express Router'),
    ],
    'flask': [
        (r'@app\.route\s*\(["\']([^"\']+)', 'Flask Route'),
        (r'@blueprint\.route\s*\(["\']([^"\']+)', 'Flask Blueprint'),
    ],
    'django': [
        (r'path\s*\(["\']([^"\']+)', 'Django URL Pattern'),
        (r're_path\s*\(["\']([^"\']+)', 'Django re_path'),
    ],
    'fastapi': [
        (r'@app\.(?:get|post|put|delete|patch)\s*\(["\']([^"\']+)', 'FastAPI Route'),
        (r'@router\.(?:get|post|put|delete|patch)\s*\(["\']([^"\']+)', 'FastAPI Router'),
    ],
}

# 인증/인가 보호 패턴
AUTH_PROTECTION_PATTERNS = {
    'spring': [
        r'@PreAuthorize',
        r'@Secured',
        r'@RolesAllowed',
        r'SecurityContextHolder',
        r'@EnableGlobalMethodSecurity',
    ],
    'express': [
        r'isAuthenticated',
        r'requireAuth',
        r'checkAuth',
        r'ensureAuth',
        r'passport\.authenticate',
        r'middleware.*auth',
        r'verifyToken',
        r'authenticateJWT',
    ],
    'flask': [
        r'@login_required',
        r'@permission_required',
        r'@requires_auth',
        r'current_user',
        r'flask_login',
        r'flask_jwt',
    ],
    'django': [
        r'@login_required',
        r'@permission_required',
        r'LoginRequiredMixin',
        r'PermissionRequiredMixin',
    ],
    'fastapi': [
        r'Depends\s*\(\s*get_current_user',
        r'Depends\s*\(\s*verify_token',
        r'Security\s*\(',
        r'HTTPBearer',
    ],
}

def detect_framework(file_path, content):
    """프레임워크 자동 감지"""
    ext = file_path.suffix.lower()
    
    if ext == '.java':
        if '@RestController' in content or '@Controller' in content:
            return 'spring'
    elif ext in ['.js', '.ts']:
        if 'express' in content.lower() or "require('express')" in content:
            return 'express'
    elif ext == '.py':
        if 'from flask' in content or 'import flask' in content:
            return 'flask'
        elif 'from django' in content or 'django.urls' in content:
            return 'django'
        elif 'from fastapi' in content or 'import fastapi' in content:
            return 'fastapi'
    
    return None

def has_auth_protection(content, framework, line_num, context_lines=15):
    """인증/인가 보호 여부 확인"""
    if framework not in AUTH_PROTECTION_PATTERNS:
        return False
    
    lines = content.split('\n')
    start = max(0, line_num - context_lines)
    end = min(len(lines), line_num + 5)
    context = '\n'.join(lines[start:end])
    
    for pattern in AUTH_PROTECTION_PATTERNS[framework]:
        if re.search(pattern, context, re.IGNORECASE):
            return True
    
    return False

def scan(project_path, target_files):
    """권한 체크 누락 탐지"""
    findings = []
    
    for file_path in target_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            framework = detect_framework(file_path, content)
            if not framework or framework not in ROUTE_PATTERNS:
                continue
            
            for line_num, line in enumerate(lines, 1):
                for pattern, description in ROUTE_PATTERNS[framework]:
                    match = re.search(pattern, line)
                    if match:
                        route_path = match.group(1)
                        
                        # 인증/인가 보호 확인
                        if not has_auth_protection(content, framework, line_num):
                            # 관리자/중요 엔드포인트 우선
                            is_critical = any(keyword in route_path.lower() for keyword in 
                                            ['admin', 'delete', 'update', 'manage', 'config', 'user', 'settings'])
                            
                            try:
                                rel_path = file_path.relative_to(project_path)
                            except:
                                rel_path = file_path
                            
                            findings.append({
                                'file': str(rel_path),
                                'line': line_num,
                                'type': f'{description} - 인증/인가 체크 누락',
                                'route': route_path,
                                'snippet': line.strip()[:100],
                                'critical': is_critical,
                                'framework': framework
                            })
        
        except:
            continue
    
    if findings:
        critical_count = sum(1 for f in findings if f.get('critical'))
        
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 보호되지 않은 엔드포인트 발견 (중요: {critical_count}개)',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **모든 엔드포인트에 인증 적용** (필수)
```java
   // Spring
   @PreAuthorize("hasRole('USER')")
   @GetMapping("/api/users")
   public List<User> getUsers() { }
   
   // Express
   app.get('/api/users', requireAuth, (req, res) => {});
   
   // Flask
   @app.route('/api/users')
   @login_required
   def get_users():
   
   // FastAPI
   @app.get("/api/users")
   async def get_users(current_user: User = Depends(get_current_user)):
```

2. **리소스 소유권 검증**
```java
   if (!resource.getOwnerId().equals(currentUserId)) {
       throw new ForbiddenException();
   }
```

3. **역할 기반 접근 제어 (RBAC)**

4. **화이트리스트 방식** (기본 deny, 명시적 allow)
            '''
        }
    
    return {'status': 'SAFE', 'details': '모든 엔드포인트가 적절히 보호됨'}