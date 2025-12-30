"""
A09: Security Logging and Monitoring Failures
보안 로깅 및 모니터링 실패
"""
import requests
import time
import random

def scan(target_url):
    result = {
        'name': 'A09: Security Logging and Monitoring Failures',
        'category': 'OWASP TOP 10 2025',
        'status': 'SAFE',
        'severity': 'LOW',
        'vulnerabilities': [],
        'recommendation': '보안 이벤트 로깅, 실시간 알림, 로그 보호 및 백업, 모니터링 대시보드',
        'details': ''
    }
    
    details = []
    
    # 1. 로그인 실패 이벤트 로깅 확인
    details.append("[로깅-1] 로그인 실패 로깅 확인")
    
    login_url = f"{target_url}/api/auth/login"
    
    try:
        failed_attempts = []
        
        # 5회 연속 실패 로그인
        for i in range(5):
            data = {'employeeId': 'test_logging', 'password': f'wrong{i}'}
            headers = {'X-Security-Mode': 'vulnerable'}
            
            start_time = time.time()
            resp = requests.post(login_url, json=data, headers=headers, timeout=5)
            elapsed = time.time() - start_time
            
            failed_attempts.append({
                'attempt': i+1,
                'status': resp.status_code,
                'time': elapsed
            })
        
        # 응답 시간 분석
        times = [a['time'] for a in failed_attempts]
        avg_time = sum(times) / len(times)
        time_variance = max(times) - min(times)
        
        # 시도 횟수에 따른 응답 시간 증가가 없으면 로깅 부재 가능성
        if time_variance < 0.1:  # 시간 차이가 거의 없음
            result['vulnerabilities'].append("로그인 실패 로깅 부재 가능성")
            details.append("  ⚠ 주의: 연속 실패 시 응답 시간 변화 없음")
            details.append(f"     평균: {avg_time:.2f}초, 편차: {time_variance:.2f}초")
            details.append("     (로깅/검증 없이 즉시 응답 가능성)")
        else:
            details.append("  ✓ 양호: 실패 시도 처리 중 (로깅 가능성)")
            details.append(f"     응답 시간 변화: {time_variance:.2f}초")
            
    except Exception as e:
        details.append(f"  • 로그인 로깅 테스트 실패")
    
    # 2. 에러 메시지 과다 노출 (정보 유출)
    details.append("\n[로깅-2] 에러 메시지 노출 확인")
    
    try:
        # 존재하지 않는 엔드포인트
        random_path = f"/api/nonexistent/{random.randint(10000, 99999)}"
        resp = requests.get(f"{target_url}{random_path}", timeout=5)
        
        # 스택 트레이스, 경로, 버전 정보 노출 확인
        sensitive_info = [
            # 파일 경로
            ('/usr/', 'Unix 경로'),
            ('/var/', 'Unix var 경로'),
            ('/home/', 'Unix home 경로'),
            ('C:\\', 'Windows 경로'),
            ('C:/', 'Windows 경로'),
            
            # 스택 트레이스
            ('at com.', 'Java 스택 트레이스'),
            ('at org.', 'Java 스택 트레이스'),
            ('Traceback', 'Python 스택 트레이스'),
            ('File "/', 'Python 파일 경로'),
            
            # 에러 메시지
            ('Warning:', 'PHP Warning'),
            ('Fatal error:', 'PHP Fatal Error'),
            ('Notice:', 'PHP Notice'),
            
            # 상세 에러
            ('SQLException', 'SQL Exception'),
            ('NullPointerException', 'Java NullPointer'),
            ('ArrayIndexOutOfBoundsException', 'Java ArrayIndex'),
            ('ClassNotFoundException', 'Java ClassNotFound'),
            
            # 프레임워크 정보
            ('org.springframework', 'Spring Framework'),
            ('javax.servlet', 'Java Servlet'),
            ('flask.app', 'Flask'),
            ('django.', 'Django'),
        ]
        
        exposed_count = 0
        exposed_types = []
        
        for pattern, desc in sensitive_info:
            if pattern in resp.text:
                exposed_count += 1
                if desc not in exposed_types:
                    exposed_types.append(desc)
        
        if exposed_count > 0:
            result['vulnerabilities'].append(f"에러 메시지에 민감 정보 노출: {exposed_count}개 항목")
            details.append(f"  ✗ 취약: 상세 에러 정보 노출")
            for etype in exposed_types[:3]:  # 최대 3개만 표시
                details.append(f"    - {etype}")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: 일반적인 에러 메시지만 노출")
            
    except:
        details.append("  • 에러 메시지 테스트 실패")
    
    # 3. 로그 파일 직접 접근 가능 여부
    details.append("\n[로깅-3] 로그 파일 노출 확인")
    
    log_paths = [
        ('/logs/access.log', 'Access Log'),
        ('/logs/error.log', 'Error Log'),
        ('/logs/application.log', 'Application Log'),
        ('/var/log/apache2/access.log', 'Apache Access'),
        ('/var/log/nginx/access.log', 'Nginx Access'),
        ('/app.log', 'App Log'),
        ('/debug.log', 'Debug Log'),
        ('/server.log', 'Server Log'),
        ('/logs/security.log', 'Security Log'),
        ('/logs/audit.log', 'Audit Log'),
    ]
    
    exposed_logs = []
    
    for log_path, log_name in log_paths:
        try:
            resp = requests.get(f"{target_url}{log_path}", timeout=5)
            
            if resp.status_code == 200 and len(resp.text) > 0:
                # 로그 파일 특성 확인
                log_indicators = ['GET', 'POST', 'HTTP', '200', '404', 'error', 'Exception', 'INFO', 'WARN']
                
                if any(indicator in resp.text for indicator in log_indicators):
                    exposed_logs.append(log_name)
                    result['vulnerabilities'].append(f"로그 파일 노출: {log_path}")
                    details.append(f"  ✗ 취약: {log_path} 접근 가능")
                    result['status'] = 'VULNERABLE'
                    
        except:
            pass
    
    if not exposed_logs:
        details.append("  ✓ 양호: 로그 파일 노출 없음")
    
    # 4. 보안 헤더 확인 (모니터링 관련)
    details.append("\n[로깅-4] 보안 관련 응답 헤더 확인")
    
    try:
        resp = requests.get(target_url, timeout=5)
        headers = resp.headers
        
        # X-Request-ID (요청 추적용)
        if 'X-Request-ID' not in headers and 'Request-ID' not in headers and 'X-Trace-ID' not in headers:
            result['vulnerabilities'].append("요청 추적 ID 없음")
            details.append("  ⚠ 주의: Request-ID 헤더 없음")
            details.append("     (로그 추적 및 디버깅 어려움)")
        else:
            request_id_header = headers.get('X-Request-ID') or headers.get('Request-ID') or headers.get('X-Trace-ID')
            details.append(f"  ✓ 양호: 요청 추적 ID 존재 ({request_id_header[:20]}...)")
        
        # Rate Limit 헤더
        rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'RateLimit',
            'RateLimit-Limit'
        ]
        
        has_rate_limit = any(h in headers for h in rate_limit_headers)
        
        if not has_rate_limit:
            details.append("  ⚠ 주의: Rate Limit 헤더 없음")
        else:
            details.append("  ✓ 양호: Rate Limit 정보 제공")
            
    except:
        details.append("  • 응답 헤더 확인 실패")
    
    # 5. 감사 로그 기능 확인
    details.append("\n[로깅-5] 감사 로그 기능 추정")
    
    try:
        audit_endpoints = [
            '/api/audit-logs',
            '/api/audit',
            '/api/logs',
            '/api/activity',
            '/api/admin/logs',
            '/api/admin/audit',
        ]
        
        audit_found = False
        
        for endpoint in audit_endpoints:
            try:
                resp = requests.get(f"{target_url}{endpoint}", timeout=5)
                
                # 존재하지만 인증 필요한 경우도 감사 로그 기능 있음
                if resp.status_code in [200, 401, 403]:
                    audit_found = True
                    details.append(f"  ✓ 양호: 감사 로그 엔드포인트 존재 ({endpoint})")
                    break
                    
            except:
                pass
        
        if not audit_found:
            result['vulnerabilities'].append("감사 로그 기능 없음")
            details.append("  ⚠ 주의: 감사 로그 API 없음")
            details.append("     (보안 이벤트 추적 어려움)")
            
    except:
        details.append("  • 감사 로그 확인 실패")
    
    # 6. 보안 이벤트 알림 테스트
    details.append("\n[로깅-6] 의심스러운 활동 탐지")
    
    try:
        # 단시간 여러 엔드포인트 접근 (스캐닝 패턴)
        scan_endpoints = [
            '/admin', '/api/admin', '/administrator',
            '/.git', '/.env', '/backup',
            '/phpmyadmin', '/wp-admin', '/admin.php',
            '/console', '/debug', '/test'
        ]
        
        for endpoint in scan_endpoints[:5]:  # 5개만 테스트
            try:
                requests.get(f"{target_url}{endpoint}", timeout=2)
                time.sleep(0.1)
            except:
                pass
        
        # 차단되거나 경고를 받았는지 확인
        final_resp = requests.get(target_url, timeout=5)
        
        if final_resp.status_code == 429:  # Too Many Requests
            details.append("  ✓ 양호: 의심스러운 활동 탐지됨 (429)")
        elif 'captcha' in final_resp.text.lower():
            details.append("  ✓ 양호: CAPTCHA 요구됨")
        elif 'blocked' in final_resp.text.lower():
            details.append("  ✓ 양호: IP 차단됨")
        else:
            details.append("  ⚠ 주의: 스캐닝 패턴 탐지 안 됨")
            details.append("     (IDS/IPS 없음 가능성)")
            
    except:
        details.append("  • 탐지 테스트 실패")
    
    # 7. 로그 보존 정책 (추정)
    details.append("\n[로깅-7] 로그 보존 정책")
    
    try:
        # 오래된 날짜로 로그 조회 시도
        old_dates = [
            '2020-01-01',
            '2021-01-01',
            '2022-01-01',
        ]
        
        log_endpoint = f"{target_url}/api/logs"
        
        for old_date in old_dates:
            params = {'date': old_date, 'from': old_date}
            
            try:
                resp = requests.get(log_endpoint, params=params, timeout=5)
                
                if resp.status_code == 200:
                    details.append(f"  • {old_date} 로그 조회 가능 (보존 기간 확인 필요)")
                    break
            except:
                pass
        
        details.append("  • 로그 보존 정책은 수동 확인 필요")
        
    except:
        pass
    
    # 8. 민감 정보 로깅 (비밀번호, 토큰 등)
    details.append("\n[로깅-8] 민감 정보 로깅 확인")
    
    try:
        # 로그인 시도
        test_password = f"test_password_{random.randint(10000, 99999)}"
        data = {'employeeId': 'test_log', 'password': test_password}
        
        resp = requests.post(login_url, json=data, timeout=5)
        
        # 응답이나 에러에 비밀번호가 그대로 노출되는지 확인
        if test_password in resp.text:
            result['vulnerabilities'].append("비밀번호가 응답에 노출됨")
            details.append("  ✗ 취약: 비밀번호가 응답에 포함됨")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: 민감 정보 마스킹됨")
        
        # 로그 파일에서도 확인 (접근 가능한 경우)
        for log_path, _ in log_paths[:3]:
            try:
                log_resp = requests.get(f"{target_url}{log_path}", timeout=5)
                
                if test_password in log_resp.text:
                    result['vulnerabilities'].append("로그 파일에 비밀번호 노출")
                    details.append(f"  ✗ 취약: {log_path}에 비밀번호 기록됨")
                    result['status'] = 'VULNERABLE'
                    break
            except:
                pass
                
    except:
        details.append("  • 민감 정보 로깅 테스트 실패")
    
    # 9. 보안 이벤트 종류
    details.append("\n[로깅-9] 보안 이벤트 로깅 범위")
    
    security_events = [
        ('로그인 실패', '인증'),
        ('권한 상승 시도', '인가'),
        ('SQL Injection 시도', '공격 탐지'),
        ('비정상 트래픽', '이상 탐지'),
    ]
    
    details.append("  • 다음 이벤트 로깅 권장:")
    for event, category in security_events:
        details.append(f"    - {event} ({category})")
    
    # 10. 로그 무결성
    details.append("\n[로깅-10] 로그 무결성 보호")
    
    try:
        # 로그 수정 시도 (실제로는 권한 필요)
        details.append("  • 로그 무결성 보호는 다음 사항 확인 필요:")
        details.append("    - Write-once 저장소 사용")
        details.append("    - 로그 서명/해시")
        details.append("    - 중앙 집중식 로깅 (SIEM)")
        details.append("    - 로그 백업 및 아카이빙")
        
    except:
        pass
    
    result['details'] = '\n'.join(details)
    return result