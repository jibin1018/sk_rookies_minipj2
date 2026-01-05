"""
CORS/CSRF 취약점
"""
import requests

def scan(target_url):
    result = {
        'name': 'CORS/CSRF 취약점',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'CORS 정책 강화, CSRF 토큰 사용',
        'details': ''
    }
    
    details = []
    
    # 1. CORS 설정 확인
    details.append("[CORS 설정]")
    
    try:
        headers = {'Origin': 'http://evil.com'}
        resp = requests.get(target_url, headers=headers, timeout=5)
        
        if 'Access-Control-Allow-Origin' in resp.headers:
            acao = resp.headers['Access-Control-Allow-Origin']
            
            if acao == '*':
                result['vulnerabilities'].append("CORS: 모든 도메인 허용")
                details.append("  ✗ Access-Control-Allow-Origin: *")
                result['status'] = 'VULNERABLE'
            elif 'evil.com' in acao:
                result['vulnerabilities'].append("CORS: Origin 검증 부족")
                details.append(f"  ✗ {acao}")
                result['status'] = 'VULNERABLE'
            else:
                details.append(f"  ✓ CORS 적절: {acao}")
        else:
            details.append("  ✓ CORS 헤더 없음")
            
    except:
        details.append("  • CORS 테스트 실패")
    
    # 2. CSRF 토큰 확인
    details.append("\n[CSRF 보호]")
    
    try:
        resp = requests.get(target_url, timeout=5)
        
        # CSRF 토큰 존재 여부
        csrf_indicators = ['csrf', 'xsrf', '_token']
        has_csrf = any(ind in resp.text.lower() for ind in csrf_indicators)
        
        if has_csrf:
            details.append("  ✓ CSRF 토큰 존재")
        else:
            result['vulnerabilities'].append("CSRF 토큰 없음")
            details.append("  ⚠ CSRF 토큰 미발견")
            
    except:
        details.append("  • CSRF 확인 실패")
    
    result['details'] = '\n'.join(details)
    return result