"""
Security Misconfiguration (보안 설정 오류)
"""
import requests

def scan(target_url):
    result = {
        'name': 'Security Misconfiguration (보안 설정 오류)',
        'category': 'OWASP A05',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '기본 설정 변경, 불필요한 기능 비활성화, 에러 메시지 최소화',
        'details': ''
    }
    
    details = []
    
    # 1. 디렉터리 리스팅
    details.append("[설정-1] 디렉터리 리스팅")
    
    test_dirs = ['/uploads/', '/files/', '/images/', '/static/']
    
    for test_dir in test_dirs:
        try:
            resp = requests.get(f"{target_url}{test_dir}", timeout=5)
            
            if 'Index of' in resp.text or '<title>Directory listing' in resp.text:
                result['vulnerabilities'].append(f"디렉터리 리스팅: {test_dir}")
                details.append(f"  ✗ {test_dir} 리스팅 허용")
                result['status'] = 'VULNERABLE'
                
        except:
            pass
    
    # 2. 상세 에러 메시지
    details.append("\n[설정-2] 에러 메시지 노출")
    
    try:
        resp = requests.get(f"{target_url}/nonexistent", timeout=5)
        
        error_indicators = ['Traceback', 'at line', 'SQLException', 'stack trace']
        
        if any(ind in resp.text for ind in error_indicators):
            result['vulnerabilities'].append("상세 에러 메시지 노출")
            details.append("  ✗ 스택 트레이스 노출")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 일반 에러 메시지")
            
    except:
        details.append("  • 에러 메시지 테스트 불가")
    
    # 3. 기본 계정
    details.append("\n[설정-3] 기본 계정 확인")
    
    default_creds = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('root', 'root'),
    ]
    
    login_url = f"{target_url}/api/auth/login"
    
    for username, password in default_creds:
        try:
            data = {'employeeId': username, 'password': password}
            resp = requests.post(login_url, json=data, timeout=5)
            
            if resp.status_code == 200 and 'token' in resp.text.lower():
                result['vulnerabilities'].append(f"기본 계정 사용: {username}/{password}")
                details.append(f"  ✗ {username}/{password} 로그인 성공")
                result['status'] = 'VULNERABLE'
                break
                
        except:
            pass
    
    result['details'] = '\n'.join(details)
    return result