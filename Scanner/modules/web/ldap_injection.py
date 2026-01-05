"""
LDAP Injection 안전 점검

LDAP 쿼리 인젝션 가능성을 안전하게 탐지합니다.
- 에러 기반 탐지
- 불완전한 쿼리 패턴
"""
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


def scan(target_url):
    result = {
        'name': 'LDAP Injection',
        'category': 'Injection',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'LDAP 쿼리 파라미터 이스케이프, 바인드 변수 사용',
        'details': ''
    }
    
    details = []
    
    # 안전한 LDAP 인젝션 페이로드 (탐지 목적)
    SAFE_PAYLOADS = [
        ('*', 'wildcard'),
        (')', 'close_paren'),
        ('(', 'open_paren'),
        ('*)(cn=*', 'filter_injection'),
        ('*)(|(cn=*', 'or_injection'),
        ('*))%00', 'null_byte'),
        ('admin)(&)', 'and_bypass'),
        ('*)(uid=*))(|(uid=*', 'nested'),
    ]
    
    # LDAP 에러 시그니처
    LDAP_ERRORS = [
        'ldap', 'invalid dn', 'invalid filter',
        'bad search filter', 'object class violation',
        'ldap_search', 'ldap_bind', 'ldap_connect',
        'active directory', 'distinguished name',
        'javax.naming', 'ldapsearch', 'cn=', 'dc=',
        'filter syntax', 'bad filter',
    ]
    
    try:
        details.append("[LDAP-1] LDAP Injection 탐지 (안전 모드)\n")
        
        # 로그인/검색 엔드포인트 탐색
        endpoints = [
            '/login', '/auth', '/search', '/user',
            '/ldap', '/directory', '/lookup',
        ]
        
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        test_endpoints = []
        
        # 기존 URL 파라미터
        if parsed.query:
            test_endpoints.append(target_url)
        
        # 일반적인 엔드포인트
        for ep in endpoints:
            test_endpoints.append(urljoin(base_url, ep + '?username=test'))
            test_endpoints.append(urljoin(base_url, ep + '?user=test'))
            test_endpoints.append(urljoin(base_url, ep + '?q=test'))
        
        vulnerable_points = []
        
        for url in test_endpoints[:5]:  # 최대 5개만
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            if not params:
                continue
            
            details.append(f"[테스트] {parsed_url.path}")
            
            for param_name in params.keys():
                for payload, payload_type in SAFE_PAYLOADS[:5]:  # 최대 5개
                    try:
                        test_params = {k: v[0] for k, v in params.items()}
                        test_params[param_name] = payload
                        
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params)}"
                        
                        response = requests.get(test_url, timeout=5, verify=False)
                        response_lower = response.text.lower()
                        
                        # LDAP 에러 감지
                        for error in LDAP_ERRORS:
                            if error in response_lower:
                                vulnerable_points.append({
                                    'param': param_name,
                                    'payload': payload_type,
                                    'error': error
                                })
                                details.append(f"    ✗ LDAP 에러 감지: {error}")
                                break
                        
                    except:
                        continue
        
        # 요약
        details.append("\n[LDAP-2] 보안 요약")
        
        if vulnerable_points:
            result['status'] = 'VULNERABLE'
            result['vulnerabilities'] = [
                f"LDAP Injection: {v['param']} ({v['error']})"
                for v in vulnerable_points
            ]
            details.append(f"\n  ✗ 취약점: {len(vulnerable_points)}개")
        else:
            details.append("\n  ✓ LDAP Injection 취약점 미발견")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
