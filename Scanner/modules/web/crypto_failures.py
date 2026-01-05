"""
Cryptographic Failures (암호화 실패)
"""
import requests

def scan(target_url):
    result = {
        'name': 'Cryptographic Failures (암호화 실패)',
        'category': 'OWASP A02',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': 'HTTPS 사용, 강력한 해시 함수, 민감 데이터 암호화',
        'details': ''
    }
    
    details = []
    
    # 1. HTTP 사용
    details.append("[암호화-1] HTTPS 사용 확인")
    
    if target_url.startswith('http://'):
        result['vulnerabilities'].append("HTTP 사용 (암호화되지 않은 통신)")
        details.append("  ✗ HTTP 프로토콜 사용 중")
        result['status'] = 'VULNERABLE'
    else:
        details.append("  ✓ HTTPS 사용")
    
    # 2. 민감 정보 헤더 노출
    details.append("\n[암호화-2] 서버 정보 노출")
    
    try:
        resp = requests.get(target_url, timeout=5)
        
        if 'Server' in resp.headers:
            result['vulnerabilities'].append(f"서버 정보 노출: {resp.headers['Server']}")
            details.append(f"  ✗ Server: {resp.headers['Server']}")
            result['status'] = 'VULNERABLE'
        
        if 'X-Powered-By' in resp.headers:
            result['vulnerabilities'].append(f"기술 스택 노출: {resp.headers['X-Powered-By']}")
            details.append(f"  ✗ X-Powered-By: {resp.headers['X-Powered-By']}")
            result['status'] = 'VULNERABLE'
            
    except:
        details.append("  • 헤더 확인 실패")
    
    # 3. 보안 헤더 확인
    details.append("\n[암호화-3] 보안 헤더 확인")
    
    try:
        resp = requests.get(target_url, timeout=5)
        
        required_headers = {
            'Strict-Transport-Security': 'HSTS',
            'X-Content-Type-Options': 'Content-Type Sniffing 방지',
            'X-Frame-Options': 'Clickjacking 방지',
        }
        
        for header, desc in required_headers.items():
            if header not in resp.headers:
                result['vulnerabilities'].append(f"{desc} 헤더 없음")
                details.append(f"  ✗ {header} 미설정")
                result['status'] = 'VULNERABLE'
            else:
                details.append(f"  ✓ {header} 설정됨")
                
    except:
        details.append("  • 보안 헤더 확인 실패")
    
    result['details'] = '\n'.join(details)
    return result