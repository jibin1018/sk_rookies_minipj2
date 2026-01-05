"""
A04: Insecure Design (안전하지 않은 설계)
설계 단계의 보안 결함 탐지
"""
import requests
import time
import hashlib
import random

def scan(target_url):
    result = {
        'name': 'A04: Insecure Design (안전하지 않은 설계)',
        'category': 'OWASP TOP 10 2025',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '비즈니스 로직 보안 강화, 레이트 리미팅, 안전한 토큰 설계, 트랜잭션 검증',
        'details': ''
    }
    
    details = []
    
    # 1. 비밀번호 재설정 토큰 예측 가능성
    details.append("[설계-1] 비밀번호 재설정 토큰 보안")
    
    try:
        reset_url = f"{target_url}/api/auth/password-reset"
        
        # 여러 번 요청하여 토큰 패턴 분석
        tokens_found = []
        emails = [f'test{i}@example.com' for i in range(5)]
        
        for email in emails:
            data = {'email': email}
            headers = {'X-Security-Mode': 'vulnerable'}
            
            resp = requests.post(reset_url, json=data, headers=headers, timeout=5)
            
            if resp.status_code == 200:
                # 응답에서 토큰 추출 시도
                if 'token' in resp.text.lower():
                    # 토큰이 노출되는 경우
                    result['vulnerabilities'].append("비밀번호 재설정 토큰이 응답에 노출됨")
                    details.append("  ✗ 취약: 토큰이 API 응답에 포함됨")
                    result['status'] = 'VULNERABLE'
                    break
                
                # 토큰이 이메일로만 전송되는지 확인
                if 'email sent' in resp.text.lower() or 'sent to' in resp.text.lower():
                    details.append("  ✓ 토큰이 이메일로만 전송됨")
        
        # 순차적 토큰 테스트
        sequential_tokens = ['1', '2', '3', '12345', '123456', 'abc123']
        verify_url = f"{target_url}/api/auth/verify-reset-token"
        
        for token in sequential_tokens:
            data = {'token': token}
            headers = {'X-Security-Mode': 'vulnerable'}
            resp = requests.post(verify_url, json=data, headers=headers, timeout=5)
            
            if resp.status_code == 200 and 'valid' in resp.text.lower():
                result['vulnerabilities'].append(f"예측 가능한 재설정 토큰: {token}")
                details.append(f"  ✗ 취약: 순차적 토큰({token}) 유효함")
                result['status'] = 'VULNERABLE'
                break
        
        # 타임스탬프 기반 토큰 테스트
        timestamp = int(time.time())
        time_tokens = [
            str(timestamp),
            hashlib.md5(str(timestamp).encode()).hexdigest()[:8],
            f"{timestamp}",
        ]
        
        for token in time_tokens:
            data = {'token': token}
            resp = requests.post(verify_url, json=data, timeout=5)
            
            if resp.status_code == 200:
                result['vulnerabilities'].append("타임스탬프 기반 토큰 (예측 가능)")
                details.append(f"  ✗ 타임스탬프 기반 토큰 사용")
                result['status'] = 'VULNERABLE'
                break
        
        if result['status'] == 'SAFE':
            details.append("  ✓ 양호: 재설정 토큰 보안 적절")
            
    except Exception as e:
        details.append(f"  • 비밀번호 재설정 기능 테스트 불가")
    
    # 2. 레이트 리미팅 부재 (무차별 대입 공격)
    details.append("\n[설계-2] 레이트 리미팅 확인")
    
    login_url = f"{target_url}/api/auth/login"
    
    try:
        rapid_requests = 0
        start_time = time.time()
        blocked = False
        
        for i in range(30):
            data = {'employeeId': 'admin', 'password': f'wrong{i}'}
            headers = {'X-Security-Mode': 'vulnerable'}
            
            try:
                resp = requests.post(login_url, json=data, headers=headers, timeout=2)
                
                if resp.status_code == 429:  # Too Many Requests
                    details.append(f"  ✓ 양호: {i+1}번째 시도에서 레이트 리미팅 적용")
                    blocked = True
                    break
                elif resp.status_code in [401, 403, 400]:
                    rapid_requests += 1
                
            except requests.Timeout:
                pass
        
        elapsed = time.time() - start_time
        
        if not blocked:
            if rapid_requests >= 20:
                result['vulnerabilities'].append(f"레이트 리미팅 없음 ({rapid_requests}회 연속 요청 허용)")
                details.append(f"  ✗ 취약: {rapid_requests}회 무제한 요청 가능 ({elapsed:.1f}초)")
                result['status'] = 'VULNERABLE'
            elif rapid_requests >= 10:
                details.append(f"  ⚠ 주의: 레이트 리미팅이 느슨함 ({rapid_requests}회)")
        
    except Exception as e:
        details.append("  • 레이트 리미팅 테스트 실패")
    
    # 3. 비즈니스 로직 우회 (가격 조작, 수량 조작)
    details.append("\n[설계-3] 비즈니스 로직 검증")
    
    try:
        order_url = f"{target_url}/api/orders"
        
        malicious_orders = [
            {'item_id': 1, 'quantity': -1, 'test': '음수 수량'},
            {'item_id': 1, 'quantity': 0, 'test': '0 수량'},
            {'item_id': 1, 'price': -100, 'test': '음수 가격'},
            {'item_id': 1, 'price': 0.01, 'test': '매우 낮은 가격'},
            {'item_id': 1, 'quantity': 999999999, 'test': '과도한 수량'},
            {'item_id': -1, 'quantity': 1, 'test': '음수 상품 ID'},
        ]
        
        for order_data in malicious_orders:
            test_name = order_data.pop('test')
            
            headers = {'X-Security-Mode': 'vulnerable', 'Content-Type': 'application/json'}
            resp = requests.post(order_url, json=order_data, headers=headers, timeout=5)
            
            if resp.status_code in [200, 201]:
                result['vulnerabilities'].append(f"비즈니스 로직 우회: {test_name}")
                details.append(f"  ✗ 취약: {test_name} 허용됨")
                result['status'] = 'VULNERABLE'
                break
        
        if result['status'] == 'SAFE':
            details.append("  ✓ 비즈니스 로직 검증 적절")
            
    except:
        details.append("  • 비즈니스 로직 테스트 불가")
    
    # 4. 세션 타임아웃 부재
    details.append("\n[설계-4] 세션 타임아웃 확인")
    
    try:
        # 로그인
        login_data = {'employeeId': 'test_session', 'password': 'test123'}
        headers = {'X-Security-Mode': 'vulnerable'}
        
        resp = requests.post(login_url, json=login_data, headers=headers, timeout=5)
        
        if resp.status_code == 200:
            # 세션 정보 확인
            if 'Set-Cookie' in resp.headers:
                cookie_header = resp.headers['Set-Cookie']
                
                # Max-Age 또는 Expires 확인
                if 'Max-Age' not in cookie_header and 'Expires' not in cookie_header:
                    result['vulnerabilities'].append("세션 만료 시간 없음 (영구 세션)")
                    details.append("  ✗ 세션 쿠키에 만료 시간 없음")
                    result['status'] = 'VULNERABLE'
                elif 'Max-Age' in cookie_header:
                    # Max-Age 값 추출
                    import re
                    max_age_match = re.search(r'Max-Age=(\d+)', cookie_header)
                    if max_age_match:
                        max_age = int(max_age_match.group(1))
                        if max_age > 3600:  # 1시간 초과
                            details.append(f"  ⚠ 주의: 세션 타임아웃이 길음 ({max_age}초 = {max_age//60}분)")
                        else:
                            details.append(f"  ✓ 세션 타임아웃: {max_age}초")
            else:
                details.append("  • 세션 쿠키 없음")
        
    except:
        details.append("  • 세션 타임아웃 테스트 불가")
    
    # 5. 계정 열거 취약점 (Username Enumeration)
    details.append("\n[설계-5] 계정 열거 취약점 확인")
    
    try:
        # 존재하는 사용자 vs 존재하지 않는 사용자
        test_users = [
            ('admin', 'wrong_password', '존재하는 계정'),
            ('nonexistent_user_' + str(random.randint(10000, 99999)), 'wrong_password', '존재하지 않는 계정')
        ]
        
        responses = []
        
        for username, password, desc in test_users:
            data = {'employeeId': username, 'password': password}
            headers = {'X-Security-Mode': 'vulnerable'}
            
            start = time.time()
            resp = requests.post(login_url, json=data, headers=headers, timeout=5)
            elapsed = time.time() - start
            
            responses.append({
                'username': username,
                'desc': desc,
                'status': resp.status_code,
                'message': resp.text[:200],
                'time': elapsed
            })
        
        # 응답 차이 분석
        if len(responses) == 2:
            msg_diff = responses[0]['message'] != responses[1]['message']
            time_diff = abs(responses[0]['time'] - responses[1]['time'])
            
            if msg_diff:
                result['vulnerabilities'].append("계정 열거 가능 (응답 메시지 차이)")
                details.append("  ✗ 취약: 존재 여부에 따라 다른 메시지")
                details.append(f"    존재: {responses[0]['message'][:50]}...")
                details.append(f"    미존재: {responses[1]['message'][:50]}...")
                result['status'] = 'VULNERABLE'
            
            if time_diff > 0.5:
                result['vulnerabilities'].append("계정 열거 가능 (응답 시간 차이)")
                details.append(f"  ✗ 취약: 응답 시간 차이 {time_diff:.2f}초")
                result['status'] = 'VULNERABLE'
            
            if result['status'] == 'SAFE':
                details.append("  ✓ 양호: 동일한 응답")
        
    except:
        details.append("  • 계정 열거 테스트 실패")
    
    # 6. 2단계 인증 우회
    details.append("\n[설계-6] 2단계 인증 설계 확인")
    
    try:
        twofa_url = f"{target_url}/api/auth/verify-2fa"
        
        # OTP 브루트포스 가능 여부
        attempts = 0
        for code in ['000000', '111111', '123456', '999999']:
            data = {'code': code}
            resp = requests.post(twofa_url, json=data, timeout=5)
            
            if resp.status_code == 429:
                details.append(f"  ✓ 2FA 시도 횟수 제한 ({attempts+1}회)")
                break
            
            attempts += 1
        
        if attempts >= 4:
            result['vulnerabilities'].append("2FA 코드 무차별 대입 가능")
            details.append("  ✗ 취약: OTP 시도 횟수 제한 없음")
            result['status'] = 'VULNERABLE'
        
    except:
        details.append("  • 2FA 기능 없음 또는 테스트 불가")
    
    # 7. 동시 세션 제한
    details.append("\n[설계-7] 동시 세션 제한 확인")
    
    try:
        # 동일 계정으로 여러 번 로그인
        login_data = {'employeeId': 'test_concurrent', 'password': 'test123'}
        
        tokens = []
        for i in range(5):
            resp = requests.post(login_url, json=login_data, timeout=5)
            
            if resp.status_code == 200 and 'token' in resp.text.lower():
                tokens.append(resp.json().get('data', {}).get('token'))
        
        if len(tokens) >= 5:
            result['vulnerabilities'].append("동시 세션 제한 없음")
            details.append(f"  ⚠ 주의: {len(tokens)}개 동시 세션 허용")
        elif len(tokens) > 0:
            details.append(f"  ✓ 동시 세션: {len(tokens)}개 (제한됨)")
        
    except:
        details.append("  • 동시 세션 테스트 불가")
    
    # 8. CAPTCHA 없음
    details.append("\n[설계-8] CAPTCHA 확인")
    
    try:
        # 로그인 폼에서 CAPTCHA 확인
        resp = requests.get(target_url, timeout=5)
        
        captcha_indicators = ['recaptcha', 'captcha', 'hcaptcha', 'grecaptcha']
        
        has_captcha = any(indicator in resp.text.lower() for indicator in captcha_indicators)
        
        if not has_captcha:
            result['vulnerabilities'].append("CAPTCHA 없음 (봇 공격 취약)")
            details.append("  ⚠ CAPTCHA 미적용")
        else:
            details.append("  ✓ CAPTCHA 적용됨")
        
    except:
        details.append("  • CAPTCHA 확인 실패")
    
    # 9. 트랜잭션 무결성
    details.append("\n[설계-9] 트랜잭션 무결성")
    
    try:
        # Race Condition 테스트 (간단한 버전)
        # 실제로는 멀티스레딩 필요
        details.append("  • Race Condition은 부하 테스트 도구 필요")
        details.append("  • 권장: 데이터베이스 트랜잭션 격리 수준 확인")
        
    except:
        pass
    
    # 10. 비밀번호 복구 질문
    details.append("\n[설계-10] 비밀번호 복구 보안")
    
    try:
        # 보안 질문 사용 여부
        security_question_url = f"{target_url}/api/auth/security-question"
        
        resp = requests.get(security_question_url, timeout=5)
        
        if resp.status_code == 200:
            # 보안 질문이 있다면
            weak_questions = [
                '어머니의 성함은?',
                '첫 애완동물 이름은?',
                '출신 학교는?',
            ]
            
            for question in weak_questions:
                if question in resp.text:
                    result['vulnerabilities'].append("약한 보안 질문 (소셜 엔지니어링 취약)")
                    details.append(f"  ⚠ 약한 보안 질문 사용")
                    break
        
    except:
        details.append("  • 보안 질문 기능 없음")
    
    result['details'] = '\n'.join(details)
    return result