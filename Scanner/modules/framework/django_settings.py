"""
Django 보안 설정 점검

Django 설정에서 흔한 보안 취약점을 점검
"""
import requests
from urllib.parse import urljoin


def scan(target_url):
    result = {
        'name': 'Django 보안 설정 점검',
        'category': 'Framework Security',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'DEBUG=False, ALLOWED_HOSTS 설정, CSRF/XSS 보호 활성화',
        'details': ''
    }
    
    details = []
    
    try:
        # 1. Django 디버그 모드 확인
        details.append("[Django-1] 디버그 모드 확인")
        
        # 존재하지 않는 URL 요청으로 에러 페이지 확인
        error_urls = [
            '/nonexistent-page-12345/',
            '/admin/does-not-exist/',
            '/__debug__/',
        ]
        
        debug_mode = False
        for url in error_urls:
            try:
                response = requests.get(
                    urljoin(target_url, url), 
                    timeout=5, 
                    verify=False
                )
                
                # Django 디버그 페이지 시그니처
                debug_signatures = [
                    'You\'re seeing this error because you have',
                    'Django tried these URL patterns',
                    'Request Method:',
                    'Request URL:',
                    'Django Version:',
                    'Exception Type:',
                    'traceback',
                ]
                
                for sig in debug_signatures:
                    if sig in response.text:
                        debug_mode = True
                        break
                        
                if debug_mode:
                    break
                    
            except requests.RequestException:
                continue
        
        if debug_mode:
            result['status'] = 'VULNERABLE'
            result['severity'] = 'CRITICAL'
            result['vulnerabilities'].append("Django DEBUG=True 활성화")
            details.append("  ✗ DEBUG 모드 활성화 (프로덕션 환경에서 반드시 비활성화)")
        else:
            details.append("  ✓ DEBUG 모드 비활성화")
        
        # 2. Django Admin 노출 확인
        details.append("\n[Django-2] Django Admin 노출 확인")
        
        admin_urls = ['/admin/', '/admin/login/', '/django-admin/']
        admin_exposed = False
        
        for url in admin_urls:
            try:
                response = requests.get(
                    urljoin(target_url, url),
                    timeout=5,
                    verify=False,
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    if 'Django' in response.text or 'csrfmiddlewaretoken' in response.text:
                        admin_exposed = True
                        details.append(f"  ⚠ Admin 페이지 노출: {url}")
                        break
                        
            except requests.RequestException:
                continue
        
        if admin_exposed:
            result['vulnerabilities'].append("Django Admin 외부 노출")
            if result['status'] == 'SAFE':
                result['status'] = 'VULNERABLE'
                result['severity'] = 'MEDIUM'
        else:
            details.append("  ✓ Admin 페이지 미노출 또는 비표준 경로")
        
        # 3. CSRF 토큰 확인
        details.append("\n[Django-3] CSRF 보호 확인")
        
        try:
            response = requests.get(target_url, timeout=5, verify=False)
            
            if 'csrftoken' in response.cookies:
                details.append("  ✓ CSRF 토큰 활성화")
                
                # CSRF 쿠키 보안 플래그 확인
                csrf_cookie = response.cookies.get('csrftoken')
                if csrf_cookie:
                    details.append(f"    쿠키 설정 확인됨")
            else:
                details.append("  ⚠ CSRF 토큰 미감지 (비활성화 또는 미사용)")
                
        except requests.RequestException:
            pass
        
        # 4. 보안 헤더 확인
        details.append("\n[Django-4] Django 보안 헤더")
        
        try:
            response = requests.get(target_url, timeout=5, verify=False)
            headers = response.headers
            
            # X-Frame-Options
            if 'X-Frame-Options' in headers:
                details.append(f"  ✓ X-Frame-Options: {headers['X-Frame-Options']}")
            else:
                details.append("  ⚠ X-Frame-Options 미설정")
            
            # X-Content-Type-Options
            if 'X-Content-Type-Options' in headers:
                details.append(f"  ✓ X-Content-Type-Options: {headers['X-Content-Type-Options']}")
            else:
                details.append("  ⚠ X-Content-Type-Options 미설정")
                
        except requests.RequestException:
            pass
        
        # 5. 정적 파일 경로 노출
        details.append("\n[Django-5] 정적 파일 설정")
        
        static_urls = ['/static/', '/media/', '/staticfiles/']
        for url in static_urls:
            try:
                response = requests.get(
                    urljoin(target_url, url),
                    timeout=3,
                    verify=False
                )
                if response.status_code == 200 and 'Index of' in response.text:
                    details.append(f"  ⚠ 디렉토리 리스팅 노출: {url}")
                    result['vulnerabilities'].append(f"정적 파일 디렉토리 리스팅: {url}")
                    
            except requests.RequestException:
                continue
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
