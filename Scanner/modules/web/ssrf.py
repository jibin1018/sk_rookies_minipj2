"""
SSRF (Server-Side Request Forgery)
"""
import requests

def scan(target_url):
    result = {
        'name': 'SSRF (Server-Side Request Forgery)',
        'category': 'OWASP A10',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'URL 화이트리스트, Private IP 차단, DNS Rebinding 방어',
        'details': ''
    }
    
    details = []
    
    # SSRF 페이로드
    ssrf_payloads = [
        ('http://169.254.169.254/latest/meta-data/', 'AWS Metadata'),
        ('http://localhost/admin', 'Localhost'),
        ('http://127.0.0.1/admin', '127.0.0.1'),
        ('http://192.168.1.1/', 'Private IP'),
        ('file:///etc/passwd', 'File Protocol'),
    ]
    
    details.append("[SSRF 테스트]")
    
    # URL 파라미터를 받는 엔드포인트 찾기
    test_endpoints = [
        f"{target_url}/api/fetch",
        f"{target_url}/api/proxy",
        f"{target_url}/api/webhook",
    ]
    
    for endpoint in test_endpoints:
        for payload, desc in ssrf_payloads:
            try:
                params = {'url': payload}
                resp = requests.get(endpoint, params=params, timeout=5)
                
                # 내부 리소스 응답 확인
                if resp.status_code == 200 and len(resp.text) > 0:
                    indicators = ['ami-', 'instance-id', 'root:', '[boot loader]']
                    
                    if any(ind in resp.text for ind in indicators):
                        result['vulnerabilities'].append(f"SSRF: {desc}")
                        details.append(f"  ✗ {endpoint} - {desc} 접근 가능")
                        result['status'] = 'VULNERABLE'
                        
            except:
                pass
    
    if result['status'] == 'SAFE':
        details.append("  ✓ SSRF 취약점 없음")
    
    result['details'] = '\n'.join(details)
    return result