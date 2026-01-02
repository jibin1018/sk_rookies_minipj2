"""
쿠키 보안 분석

HTTP 쿠키의 보안 속성을 점검합니다.
"""
import requests
from urllib.parse import urlparse


def scan(target_url):
    result = {
        'name': '쿠키 보안 분석',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'Secure, HttpOnly, SameSite 속성 설정',
        'details': ''
    }
    
    details = []
    
    try:
        details.append("[Cookie-1] 쿠키 속성 분석\n")
        
        response = requests.get(target_url, timeout=10, verify=False)
        
        if not response.cookies:
            details.append("  • 쿠키 없음")
            result['details'] = '\n'.join(details)
            return result
        
        details.append(f"  발견된 쿠키: {len(response.cookies)}개\n")
        
        session_cookies = []
        vulnerable_cookies = []
        
        for cookie in response.cookies:
            cookie_info = {
                'name': cookie.name,
                'issues': []
            }
            
            is_session = any(s in cookie.name.lower() for s in 
                           ['session', 'sess', 'jsessionid', 'phpsessid', 'sid', 'token', 'auth'])
            
            if is_session:
                session_cookies.append(cookie.name)
            
            details.append(f"  [{cookie.name}]")
            
            # Secure 플래그
            if cookie.secure:
                details.append("    ✓ Secure: Yes")
            else:
                details.append("    ✗ Secure: No")
                cookie_info['issues'].append('no_secure')
                if is_session:
                    result['vulnerabilities'].append(f"세션 쿠키 Secure 없음: {cookie.name}")
            
            # HttpOnly 플래그
            # requests 라이브러리는 HttpOnly를 직접 지원하지 않으므로 헤더에서 확인
            set_cookie_header = response.headers.get('Set-Cookie', '')
            has_httponly = 'httponly' in set_cookie_header.lower()
            
            if has_httponly:
                details.append("    ✓ HttpOnly: Yes")
            else:
                details.append("    ⚠ HttpOnly: Unknown/No")
                cookie_info['issues'].append('no_httponly')
            
            # SameSite 속성
            if 'samesite=strict' in set_cookie_header.lower():
                details.append("    ✓ SameSite: Strict")
            elif 'samesite=lax' in set_cookie_header.lower():
                details.append("    ✓ SameSite: Lax")
            elif 'samesite=none' in set_cookie_header.lower():
                details.append("    ⚠ SameSite: None")
                cookie_info['issues'].append('samesite_none')
            else:
                details.append("    ⚠ SameSite: 미설정")
                cookie_info['issues'].append('no_samesite')
            
            # 만료 시간
            if cookie.expires:
                from datetime import datetime
                exp = datetime.fromtimestamp(cookie.expires)
                details.append(f"    만료: {exp.strftime('%Y-%m-%d')}")
            else:
                details.append("    만료: 세션 쿠키")
            
            # 도메인/경로
            if cookie.domain:
                details.append(f"    도메인: {cookie.domain}")
            if cookie.path:
                details.append(f"    경로: {cookie.path}")
            
            if cookie_info['issues']:
                vulnerable_cookies.append(cookie_info)
            
            details.append("")
        
        # 요약
        details.append("[Cookie-2] 보안 요약")
        
        if session_cookies:
            details.append(f"  세션 쿠키: {', '.join(session_cookies)}")
        
        if vulnerable_cookies:
            result['status'] = 'VULNERABLE'
            details.append(f"\n  취약한 쿠키: {len(vulnerable_cookies)}개")
            
            for vc in vulnerable_cookies:
                issues = ', '.join(vc['issues'])
                details.append(f"    - {vc['name']}: {issues}")
        else:
            details.append("\n  ✓ 모든 쿠키 보안 속성 양호")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
