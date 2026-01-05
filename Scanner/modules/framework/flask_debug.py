"""
Flask 디버그 모드 및 보안 설정 점검
"""
import requests
from urllib.parse import urljoin


def scan(target_url):
    result = {
        'name': 'Flask 디버그 모드 점검',
        'category': 'Framework Security',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': 'Flask 프로덕션 환경에서 debug=False 설정 필수',
        'details': ''
    }
    
    details = []
    
    try:
        # 1. Flask 디버거 콘솔 확인
        details.append("[Flask-1] Werkzeug 디버거 콘솔 확인")
        
        # 일반적으로 에러를 유발하는 URL
        error_urls = [
            '/nonexistent-endpoint-12345',
            '/__debug__',
            '/console',
        ]
        
        debug_mode = False
        console_exposed = False
        
        for url in error_urls:
            try:
                response = requests.get(
                    urljoin(target_url, url),
                    timeout=5,
                    verify=False
                )
                
                # Werkzeug 디버거 시그니처
                debug_signatures = [
                    'Werkzeug Debugger',
                    'Traceback (most recent call last)',
                    'The debugger caught an exception',
                    'interactive Python shell',
                    'SECRET',
                ]
                
                for sig in debug_signatures:
                    if sig in response.text:
                        debug_mode = True
                        if 'interactive' in sig.lower() or 'console' in url:
                            console_exposed = True
                        break
                        
            except requests.RequestException:
                continue
        
        if console_exposed:
            result['status'] = 'VULNERABLE'
            result['severity'] = 'CRITICAL'
            result['vulnerabilities'].append("Flask 디버그 콘솔 노출 (RCE 가능)")
            details.append("  ✗ Werkzeug 디버그 콘솔 접근 가능 (매우 위험!)")
        elif debug_mode:
            result['status'] = 'VULNERABLE'
            result['severity'] = 'HIGH'
            result['vulnerabilities'].append("Flask DEBUG 모드 활성화")
            details.append("  ✗ DEBUG 모드 활성화 (정보 유출 위험)")
        else:
            details.append("  ✓ DEBUG 모드 비활성화")
        
        # 2. Flask 기본 에러 페이지
        details.append("\n[Flask-2] 에러 페이지 정보 노출")
        
        try:
            response = requests.get(
                urljoin(target_url, '/trigger-error-12345'),
                timeout=5,
                verify=False
            )
            
            if 'flask' in response.text.lower() or 'werkzeug' in response.text.lower():
                details.append("  ⚠ Flask/Werkzeug 정보 노출")
                if result['status'] == 'SAFE':
                    result['vulnerabilities'].append("Flask 프레임워크 정보 노출")
                    result['status'] = 'VULNERABLE'
                    result['severity'] = 'LOW'
            else:
                details.append("  ✓ 프레임워크 정보 숨김")
                
        except requests.RequestException:
            pass
        
        # 3. Secret Key 노출 확인
        details.append("\n[Flask-3] Secret Key 노출 확인")
        
        try:
            response = requests.get(target_url, timeout=5, verify=False)
            
            # Secret Key가 노출된 경우의 시그니처
            if 'SECRET_KEY' in response.text or 'secret_key' in response.text:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'CRITICAL'
                result['vulnerabilities'].append("SECRET_KEY 노출 가능성")
                details.append("  ✗ SECRET_KEY 문자열 발견")
            else:
                details.append("  ✓ SECRET_KEY 미노출")
                
        except requests.RequestException:
            pass
        
        # 4. Flask 라우트 정보
        details.append("\n[Flask-4] 라우트 정보 노출")
        
        route_urls = ['/routes', '/sitemap', '/api/', '/swagger', '/docs']
        
        for url in route_urls:
            try:
                response = requests.get(
                    urljoin(target_url, url),
                    timeout=3,
                    verify=False
                )
                if response.status_code == 200:
                    details.append(f"  발견: {url}")
                    
            except requests.RequestException:
                continue
        
        # 5. 세션 쿠키 보안
        details.append("\n[Flask-5] 세션 쿠키 보안")
        
        try:
            response = requests.get(target_url, timeout=5, verify=False)
            
            for cookie in response.cookies:
                if 'session' in cookie.name.lower():
                    issues = []
                    if not cookie.secure:
                        issues.append("Secure 없음")
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        issues.append("HttpOnly 없음")
                    
                    if issues:
                        details.append(f"  ⚠ 세션 쿠키: {', '.join(issues)}")
                    else:
                        details.append("  ✓ 세션 쿠키 보안 플래그 설정")
                    break
                    
        except requests.RequestException:
            pass
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
