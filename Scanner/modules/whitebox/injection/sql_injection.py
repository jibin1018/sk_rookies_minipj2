#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQL Injection 탐지
"""

import re
from pathlib import Path

SQL_INJECTION_PATTERNS = {
    'python': [
        (r'execute\s*\(\s*["\'].*?%s.*?["\'].*?%', 'SQL 쿼리 문자열 포매팅'),
        (r'execute\s*\(\s*f["\'].*?SELECT.*?\{', 'SQL 쿼리 f-string 사용'),
        (r'execute\s*\(\s*.*?\.format\s*\(', 'SQL 쿼리 .format() 사용'),
        (r'execute\s*\(\s*["\'].*?["\'].*?\+', 'SQL 쿼리 문자열 연결'),
        (r'\.raw\s*\([^)]*%', 'Django raw() 쿼리 포매팅'),
        (r'executemany\s*\([^)]*%', 'executemany 포매팅'),
    ],
    'java': [
        (r'createStatement\s*\(\s*\)', 'Statement 직접 사용'),
        (r'executeQuery\s*\([^)]*\+', 'executeQuery 문자열 연결'),
        (r'executeUpdate\s*\([^)]*\+', 'executeUpdate 문자열 연결'),
        (r'createNativeQuery\s*\([^)]*\+', 'JPA Native Query 문자열 연결'),
    ],
    'php': [
        (r'mysql_query\s*\([^)]*\$', 'mysql_query 변수 직접 사용'),
        (r'mysqli_query\s*\([^)]*\$', 'mysqli_query 변수 직접 사용'),
        (r'query\s*\([^)]*\$_(?:GET|POST)', '$_GET/$_POST 직접 사용'),
        (r'->query\s*\([^)]*\$', 'PDO query 변수 사용'),
    ],
    'javascript': [
        (r'query\s*\(\s*`.*?\$\{', 'SQL 쿼리 템플릿 리터럴'),
        (r'execute\s*\(\s*`.*?\$\{', 'SQL 실행 템플릿 리터럴'),
        (r'\.query\s*\([^)]*\+', 'query() 문자열 연결'),
    ],
    'csharp': [
        (r'SqlCommand\s*\([^)]*\+', 'SqlCommand 문자열 연결'),
        (r'ExecuteNonQuery\s*\([^)]*\+', 'ExecuteNonQuery 문자열 연결'),
    ],
}

SAFE_SQL_PATTERNS = [
    r'execute\s*\([^)]+,\s*[\[\(]',  # Parameterized
    r'prepareStatement',
    r'PreparedStatement',
    r'\.prepare\s*\(',
    r'bind_param',
    r'setString\s*\(',
    r'setInt\s*\(',
]

def get_language(file_path):
    """파일 언어 판단"""
    ext = file_path.suffix.lower()
    if ext == '.py': return 'python'
    elif ext in ['.js', '.ts', '.jsx', '.tsx']: return 'javascript'
    elif ext == '.java': return 'java'
    elif ext == '.php': return 'php'
    elif ext == '.cs': return 'csharp'
    return None

def is_safe_sql(line):
    """안전한 SQL 패턴 확인"""
    for pattern in SAFE_SQL_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False

def scan(project_path, target_files):
    """SQL Injection 취약점 진단"""
    findings = []
    
    for file_path in target_files:
        language = get_language(file_path)
        if not language or language not in SQL_INJECTION_PATTERNS:
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '--', '/*', '*')):
                    continue
                
                # 안전한 패턴 체크
                if is_safe_sql(line):
                    continue
                
                for pattern, description in SQL_INJECTION_PATTERNS[language]:
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
                            'severity': 'CRITICAL',
                            'language': language
                        })
                        break
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 SQL Injection 취약점 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **Prepared Statement 사용** (필수)
```python
   # Python
   cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
   
   # Java
   PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
   pstmt.setInt(1, userId);
   
   # PHP
   $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
   $stmt->execute(['id' => $userId]);
   
   # Node.js
   const result = await db.query("SELECT * FROM users WHERE id = $1", [userId]);
```

2. **ORM 사용**
   - SQLAlchemy, Django ORM, Hibernate, Sequelize

3. **입력값 검증**
   - 화이트리스트 기반 검증

4. **최소 권한 원칙**
            '''
        }
    
    return {'status': 'SAFE', 'details': 'SQL Injection 취약점 없음'}