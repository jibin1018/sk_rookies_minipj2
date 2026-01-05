#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
메서드 단위 보안 미적용 탐지
- Service/Business 레이어에 보안 어노테이션 누락
"""

import re
from pathlib import Path

# 중요 메서드 패턴
CRITICAL_METHOD_PATTERNS = [
    (r'def\s+(delete|remove|update|modify|create|add)\w*\s*\(', 'Python 중요 메서드'),
    (r'public\s+\w+\s+(delete|remove|update|create|add)\w*\s*\(', 'Java 중요 메서드'),
    (r'function\s+(delete|remove|update|create)\w*\s*\(', 'JavaScript 중요 함수'),
    (r'async\s+function\s+(delete|remove|update)\w*\s*\(', 'Async 중요 함수'),
]

# 메서드 보안 패턴
METHOD_SECURITY_PATTERNS = [
    r'@PreAuthorize',
    r'@Secured',
    r'@RolesAllowed',
    r'@permission_required',
    r'@requires_permission',
    r'@check_permission',
]

def scan(project_path, target_files):
    """메서드 단위 보안 탐지"""
    findings = []
    
    # Service 레이어 파일 검사
    service_files = [f for f in target_files if 'service' in str(f).lower()]
    
    for file_path in service_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                for pattern, description in CRITICAL_METHOD_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        # 보안 어노테이션 확인
                        prev_lines = lines[max(0, line_num-5):line_num]
                        has_security = any(
                            re.search(p, pline) 
                            for p in METHOD_SECURITY_PATTERNS 
                            for pline in prev_lines
                        )
                        
                        if not has_security:
                            try:
                                rel_path = file_path.relative_to(project_path)
                            except:
                                rel_path = file_path
                            
                            findings.append({
                                'file': str(rel_path),
                                'line': line_num,
                                'type': f'{description} - 보안 어노테이션 누락',
                                'snippet': line.strip()[:100]
                            })
        
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 메서드에 보안 적용 누락',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **메서드 레벨 보안 적용**
```java
   @Service
   public class UserService {
       @PreAuthorize("hasRole('ADMIN')")
       public void deleteUser(Long userId) {
           userRepository.deleteById(userId);
       }
       
       @PreAuthorize("#userId == authentication.principal.id or hasRole('ADMIN')")
       public void updateUser(Long userId, UserDto dto) {
           // ...
       }
   }
```

2. **Global Method Security 활성화**
```java
   @Configuration
   @EnableGlobalMethodSecurity(prePostEnabled = true)
   public class SecurityConfig {
   }
```

3. **Python 데코레이터**
```python
   @permission_required('app.delete_user')
   def delete_user(user_id):
       User.objects.filter(id=user_id).delete()
```
            '''
        }
    
    return {'status': 'SAFE', 'details': '메서드 보안 적용됨'}