"""
세션 타임아웃 점검

세션 만료 설정 및 보안을 점검합니다.
"""
import requests
import time
from urllib.parse import urljoin


def scan(target_url):
    result = {
        'name': '세션 타임아웃 점검',
        'category': 'Session Security',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '적절한 세션 만료 시간 설정 (15-30분)',
        'details': ''
    }
    
    details = []
    
    try:
        details.append("[Session-1] 세션 설정 분석\n")
        
        session = requests.Session()
        response = session.get(target_url, timeout=10, verify=False)
        
        # 세션 쿠키 탐지
        session_cookies = []
        for cookie in session.cookies:
            name = cookie.name.lower()
            if any(s in name for s in ['session', 'sess', 'sid', 'token', 'auth', 'jwt']):
                session_cookies.append({
                    'name': cookie.name,
                    'expires': cookie.expires,
                    'max_age': None,
                    'domain': cookie.domain
                })
        
        if not session_cookies:
            details.append("  세션 쿠키 미발견")
            result['details'] = '\n'.join(details)
            return result
        
        # 세션 쿠키 분석
        for cookie in session_cookies:
            details.append(f"\n  쿠키: {cookie['name']}")
            
            if cookie['expires']:
                from datetime import datetime
                expire_time = datetime.fromtimestamp(cookie['expires'])
                now = datetime.now()
                lifetime = (expire_time - now).total_seconds()
                
                hours = lifetime / 3600
                details.append(f"    만료: {expire_time.strftime('%Y-%m-%d %H:%M')}")
                details.append(f"    수명: {hours:.1f}시간")
                
                # 권장: 15-30분
                if hours > 24:
                    result['vulnerabilities'].append(f"과도한 세션 수명: {hours:.1f}시간")
                    details.append(f"    ⚠ 너무 긴 세션 수명 (24시간 초과)")
                elif hours > 2:
                    details.append(f"    ⚠ 긴 세션 수명 (2시간 초과)")
                else:
                    details.append(f"    ✓ 적절한 세션 수명")
            else:
                details.append(f"    만료: 세션 쿠키 (브라우저 종료 시)")
        
        # 세션 관련 헤더 확인
        details.append("\n[Session-2] 세션 보안 헤더")
        
        headers = response.headers
        
        # Cache-Control
        cache_control = headers.get('Cache-Control', '')
        if 'no-store' in cache_control or 'private' in cache_control:
            details.append("  ✓ Cache-Control: 세션 캐싱 방지")
        else:
            details.append("  ⚠ Cache-Control: 세션 캐싱 가능")
        
        # Pragma
        pragma = headers.get('Pragma', '')
        if 'no-cache' in pragma:
            details.append("  ✓ Pragma: no-cache")
        
        # Set-Cookie 헤더 분석
        set_cookie = headers.get('Set-Cookie', '')
        if 'SameSite' in set_cookie:
            if 'SameSite=Strict' in set_cookie:
                details.append("  ✓ SameSite=Strict")
            elif 'SameSite=Lax' in set_cookie:
                details.append("  ✓ SameSite=Lax")
            elif 'SameSite=None' in set_cookie:
                details.append("  ⚠ SameSite=None")
        
        # 로그아웃 엔드포인트 확인
        details.append("\n[Session-3] 로그아웃 기능")
        
        logout_paths = ['/logout', '/signout', '/auth/logout', '/api/logout']
        logout_found = False
        
        for path in logout_paths:
            try:
                resp = requests.get(
                    urljoin(target_url, path),
                    timeout=5,
                    verify=False,
                    allow_redirects=False
                )
                if resp.status_code in [200, 302, 303]:
                    logout_found = True
                    details.append(f"  ✓ 로그아웃 엔드포인트: {path}")
                    break
            except:
                continue
        
        if not logout_found:
            details.append("  ⚠ 로그아웃 엔드포인트 미발견")
        
        # 요약
        details.append("\n[Session-4] 보안 요약")
        
        if result['vulnerabilities']:
            result['status'] = 'VULNERABLE'
            details.append(f"\n  취약점: {len(result['vulnerabilities'])}개")
        else:
            details.append("\n  ✓ 세션 설정 양호")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
