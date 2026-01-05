#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDOR (Insecure Direct Object Reference) 탐지
- userId, id 등 파라미터로 타인 리소스 접근 가능 패턴
"""

import re
from pathlib import Path

# IDOR 취약 패턴
IDOR_PATTERNS = [
    # 직접 ID로 조회 (소유권 검증 없음)
    (r'findById\s*\(\s*(?:request|req|params|pathVariable)\.\w+', 'findById에 request 파라미터 직접 사용'),
    (r'getById\s*\(\s*(?:request|req|params)\.\w+', 'getById에 request 파라미터 직접 사용'),
    (r'\.get\s*\(\s*(?:id|userId|request)', 'get()에 ID 파라미터 직접 사용'),
    (r'query\.get\s*\(\s*(?:id|user_?id)', 'query.get()에 ID 직접 사용'),
    
    # SQL에서 직접 조회
    (r'WHERE\s+id\s*=\s*\$\{', 'WHERE id에 템플릿 리터럴 직접 사용'),
    (r'WHERE\s+user_?id\s*=\s*\$\{', 'WHERE user_id에 템플릿 리터럴'),
    (r'WHERE\s+id\s*=\s*:id\b', 'WHERE id에 파라미터 바인딩 (소유권 검증 필요)'),
    
    # ORM 직접 조회
    (r'User\.objects\.get\s*\(\s*id\s*=', 'Django ORM get(id=) 직접 사용'),
    (r'\.findOne\s*\(\s*\{\s*_id\s*:', 'MongoDB findOne({_id:}) 직접 사용'),
    
    # 파일/리소스 접근
    (r'sendFile\s*\([^)]*(?:request|req|params)', 'sendFile에 request 파라미터'),
    (r'download\s*\([^)]*(?:request|req)', 'download에 request 파라미터'),
    (r'readFile\s*\([^)]*(?:request|req)', 'readFile에 request 파라미터'),
]

# 안전한 패턴 (소유권 검증)
SAFE_OWNERSHIP_PATTERNS = [
    r'\.getOwnerId\s*\(',
    r'\.getUserId\s*\(',
    r'checkOwnership',
    r'verifyOwnership',
    r'isOwner',
    r'belongsTo',
    r'hasAccess',
    r'canAccess',
    r'currentUser\.id\s*==',
    r'userId\s*===?\s*resource',
    r'user_id\s*==\s*current_user',
    r'ForbiddenException',
    r'UnauthorizedException',
    r'AccessDenied',
    r'PermissionDenied',
    r'if\s+not\s+.*\.owner',
    r'filter\s*\(\s*user\s*=\s*request\.user',
]

def has_ownership_check(content, line_num, context_lines=20):
    """소유권 검증 로직 존재 확인"""
    lines = content.split('\n')
    start = max(0, line_num - 5)
    end = min(len(lines), line_num + context_lines)
    context = '\n'.join(lines[start:end])
    
    for pattern in SAFE_OWNERSHIP_PATTERNS:
        if re.search(pattern, context, re.IGNORECASE):
            return True
    
    return False

def scan(project_path, target_files):
    """IDOR 취약점 탐지"""
    findings = []
    
    for file_path in target_files:
        # API/Controller/Service 파일만 검사
        if not any(keyword in str(file_path).lower() for keyword in 
                  ['controller', 'api', 'route', 'handler', 'service', 'view']):
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '/*', '*')):
                    continue
                
                for pattern, description in IDOR_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        # 소유권 검증 확인
                        if has_ownership_check(content, line_num):
                            continue
                        
                        try:
                            rel_path = file_path.relative_to(project_path)
                        except:
                            rel_path = file_path
                        
                        findings.append({
                            'file': str(rel_path),
                            'line': line_num,
                            'type': description,
                            'snippet': line.strip()[:120]
                        })
                        break
        
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 IDOR 취약점 의심',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **리소스 소유권 검증 필수**
```java
   // Spring
   Resource resource = resourceRepository.findById(resourceId)
       .orElseThrow(() -> new NotFoundException());
   
   if (!resource.getOwnerId().equals(currentUser.getId())) {
       throw new ForbiddenException("접근 권한이 없습니다");
   }
   
   // Python/Django
   resource = Resource.objects.get(id=resource_id)
   if resource.owner != request.user:
       raise PermissionDenied()
   
   // Node.js/Express
   const resource = await Resource.findById(req.params.id);
   if (resource.userId !== req.user.id) {
       return res.status(403).json({ error: 'Forbidden' });
   }
```

2. **ORM 필터 활용**
```python
   # Django - 자동으로 현재 사용자 리소스만 조회
   resource = Resource.objects.get(id=resource_id, owner=request.user)
```

3. **간접 참조 사용**
   - 순차 ID 대신 UUID 사용
   - 세션 기반 리소스 목록

4. **감사 로그 기록**
            '''
        }
    
    return {'status': 'SAFE', 'details': 'IDOR 취약점 없음'}