#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
에러 응답 정보 노출 탐지
"""

import re
from pathlib import Path

ERROR_DISCLOSURE_PATTERNS = [
    # 상세 에러 응답
    (r'return.*?(?:str\(e\)|error\.message|exception)', '에러 메시지 직접 반환'),
    (r'res\.send\s*\(\s*err', 'Express에서 에러 객체 직접 전송'),
    (r'response\.write\s*\([^)]*exception', '예외 객체 직접 출력'),
    
    # 스택 트레이스 노출
    (r'traceback\.format_exc\s*\(\s*\)', 'traceback 노출'),
    (r'printStackTrace\s*\(\s*\)', 'Java printStackTrace'),
    (r'console\.error\s*\(\s*err\.stack', 'console.error에 stack'),
    
    # 디버그 정보
    (r'__file__', '__file__ 경로 노출 가능'),
    (r'__name__', '__name__ 노출'),
]

# 안전한 에러 처리 패턴
SAFE_ERROR_PATTERNS = [
    r'user-friendly',
    r'generic.*?error',
    r'sanitize',
    r'mask',
    r'log\.error',
    r'logger\.error',
]

def has_safe_error_handling(content, line_num, context_lines=10):
    """안전한 에러 처리 확인"""
    lines = content.split('\n')
    start = max(0, line_num - 5)
    end = min(len(lines), line_num + context_lines)
    context = '\n'.join(lines[start:end])
    
    for pattern in SAFE_ERROR_PATTERNS:
        if re.search(pattern, context, re.IGNORECASE):
            return True
    
    return False

def scan(project_path, target_files):
    """에러 정보 노출 진단"""
    findings = []
    
    for file_path in target_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith(('#', '//', '/*', '*')):
                    continue
                
                for pattern, description in ERROR_DISCLOSURE_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        # 안전한 처리 확인
                        if has_safe_error_handling(content, line_num):
                            continue
                        
                        try:
                            rel_path = file_path.relative_to(project_path)
                        except:
                            rel_path = file_path
                        
                        findings.append({
                            'file': str(rel_path),
                            'line': line_num,
                            'type': description,
                            'snippet': line.strip()[:100]
                        })
                        break
        except:
            continue
    
    if findings:
        return {
            'status': 'VULNERABLE',
            'details': f'{len(findings)}개의 에러 정보 노출 발견',
            'findings': findings,
            'recommendation': '''
[권장 보안 대책]

1. **일반화된 에러 메시지** (필수)
```python
   # 나쁨
   return jsonify({'error': str(e)}), 500
   
   # 좋음
   logger.error(f"Error: {str(e)}")  # 서버 로그에만
   return jsonify({'error': 'An error occurred'}), 500
```

2. **에러 코드 사용**
```python
   ERROR_CODES = {
       'DB_ERROR': 'Database operation failed',
       'AUTH_ERROR': 'Authentication failed',
       'VALIDATION_ERROR': 'Invalid input'
   }
   
   return jsonify({'error_code': 'DB_ERROR'}), 500
```

3. **중앙화된 에러 핸들러**
```python
   @app.errorhandler(Exception)
   def handle_error(e):
       logger.exception(e)  # 서버 로그
       
       if isinstance(e, CustomException):
           return jsonify({'error': e.user_message}), e.status_code
       
       # 일반 에러는 상세 정보 숨김
       return jsonify({'error': 'Internal server error'}), 500
```

4. **환경별 에러 처리**
```python
   if app.debug:
       # 개발 환경: 상세 에러
       return jsonify({'error': str(e), 'trace': traceback.format_exc()})
   else:
       # 운영 환경: 일반 메시지
       return jsonify({'error': 'An error occurred'})
```

5. **스택 트레이스는 로그에만**
```python
   try:
       # ...
   except Exception as e:
       logger.exception("Detailed error")  # 로그에만
       return "Error occurred", 500  # 사용자에게는 간단히
```
            '''
        }
    
    return {'status': 'SAFE', 'details': '에러 정보 노출 없음'}