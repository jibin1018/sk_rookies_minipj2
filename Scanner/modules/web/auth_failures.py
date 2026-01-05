"""
Authentication Failures (인증 실패)
"""
import requests
import time

def scan(target_url):
    result = {
        'name': 'Authentication Failures (인증 실패)',
        'category': 'OWASP A07',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '강력한 비밀번호 정책, MFA, 세션 관리 강화',
        'details': ''
    }
    
    details = []
    
    # 1. Brute Force 방어
    details.append("[인증-1] Brute Force 방어")
    
    login_url = f"{target_url}/api/auth/login"
    failed_count = 0
    
    try:
        for i in range(10):
            data = {'employeeId': 'admin', 'password': f'wrong{i}'}
            resp = requests.post(login_url, json=data, timeout=5)
            
            if resp.status_code == 429:
                details.append(f"  ✓ {i+1}회 시도 후 차단")
                break
            elif resp.status_code in [401, 403]:
                failed_count += 1
        
        if failed_count >= 10:
            result['vulnerabilities'].append("Brute Force 방어 없음")
            details.append("  ✗ 10회 이상 무제한 시도 가능")
            result['status'] = 'VULNERABLE'
            
    except:
        details.append("  • Brute Force 테스트 실패")
    
    # 2. 약한 비밀번호
    details.append("\n[인증-2] 약한 비밀번호 허용")
    
    weak_passwords = ['1', '123', 'test', 'admin']
    
    try:
        signup_url = f"{target_url}/api/auth/signup"
        
        for pwd in weak_passwords:
            data = {
                'employeeId': f'test_{pwd}',
                'password': pwd,
                'name': 'Test'
            }
            resp = requests.post(signup_url, json=data, timeout=5)
            
            if resp.status_code in [200, 201]:
                result['vulnerabilities'].append(f"약한 비밀번호 허용: '{pwd}'")
                details.append(f"  ✗ '{pwd}' 비밀번호 허용")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • 비밀번호 정책 테스트 불가")
    
    result['details'] = '\n'.join(details)
    return result