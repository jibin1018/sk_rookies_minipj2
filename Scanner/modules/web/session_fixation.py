"""
세션 고정 공격 (Session Fixation) 점검

로그인 전후 세션 ID 변경 여부를 확인합니다.
"""
import requests
from urllib.parse import urljoin


def scan(target_url):
    result = {
        'name': '세션 고정 공격 점검',
        'category': 'Session Security',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '로그인 성공 시 새로운 세션 ID 발급',
        'details': ''
    }
    
    details = []
    
    # 세션 쿠키 이름 후보
    SESSION_COOKIE_NAMES = [
        'PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId',
        'session', 'sessionid', 'sid', 'sess',
        'connect.sid', 'ci_session', 'laravel_session',
    ]
    
    try:
        details.append("[Session-1] 세션 쿠키 분석\n")
        
        # 초기 요청으로 세션 쿠키 획득
        session = requests.Session()
        response = session.get(target_url, timeout=10, verify=False)
        
        initial_cookies = {}
        session_cookie_name = None
        
        for cookie in session.cookies:
            name = cookie.name.lower()
            for session_name in SESSION_COOKIE_NAMES:
                if session_name.lower() in name or name in session_name.lower():
                    session_cookie_name = cookie.name
                    initial_cookies[cookie.name] = cookie.value
                    details.append(f"  세션 쿠키 발견: {cookie.name}")
                    details.append(f"    초기 값: {cookie.value[:20]}...")
                    break
        
        if not session_cookie_name:
            details.append("  세션 쿠키 미발견")
            details.append("  ※ 로그인 폼이 필요할 수 있음")
            result['details'] = '\n'.join(details)
            return result
        
        # 로그인 폼 탐색
        details.append("\n[Session-2] 로그인 폼 탐색")
        
        login_paths = ['/login', '/signin', '/auth/login', '/user/login', '/admin/login']
        login_url = None
        
        for path in login_paths:
            url = urljoin(target_url, path)
            try:
                resp = requests.get(url, timeout=5, verify=False)
                if resp.status_code == 200:
                    if 'password' in resp.text.lower() and 'login' in resp.text.lower():
                        login_url = url
                        details.append(f"  로그인 폼: {path}")
                        break
            except:
                continue
        
        if not login_url:
            details.append("  로그인 폼 미발견")
        
        # 세션 고정 테스트 시뮬레이션
        details.append("\n[Session-3] 세션 고정 취약점 분석")
        
        # 동일 세션으로 여러 요청 시 ID 고정 여부
        session2 = requests.Session()
        
        # 세션 ID 강제 설정 시도
        forced_session_id = "FORCED_SESSION_12345"
        session2.cookies.set(session_cookie_name, forced_session_id)
        
        response2 = session2.get(target_url, timeout=10, verify=False)
        
        new_session_value = None
        for cookie in session2.cookies:
            if cookie.name == session_cookie_name:
                new_session_value = cookie.value
                break
        
        if new_session_value:
            if new_session_value == forced_session_id:
                result['vulnerabilities'].append("서버가 클라이언트 제공 세션 ID 수용")
                result['status'] = 'VULNERABLE'
                details.append("  ✗ 서버가 임의 세션 ID를 수용함")
                details.append("    세션 고정 공격에 취약할 수 있음")
            else:
                details.append("  ✓ 서버가 새 세션 ID를 발급함")
                details.append(f"    요청: {forced_session_id[:20]}...")
                details.append(f"    응답: {new_session_value[:20]}...")
        
        # 추가 점검사항
        details.append("\n[Session-4] 추가 점검")
        
        # 세션 쿠키 속성 확인
        for cookie in session.cookies:
            if cookie.name == session_cookie_name:
                if not cookie.secure:
                    result['vulnerabilities'].append("세션 쿠키 Secure 속성 없음")
                    details.append("  ⚠ Secure 속성 없음 (HTTPS 미강제)")
                else:
                    details.append("  ✓ Secure 속성 설정됨")
        
        # 요약
        details.append("\n[Session-5] 보안 요약")
        
        if result['vulnerabilities']:
            result['status'] = 'VULNERABLE'
            details.append(f"\n  취약점: {len(result['vulnerabilities'])}개")
        else:
            details.append("\n  ✓ 세션 고정 취약점 미발견")
            details.append("    ※ 실제 로그인 플로우 테스트 권장")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
