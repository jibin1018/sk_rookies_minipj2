"""
Broken Access Control (접근 제어 취약점)
IDOR, 권한 상승, 강제 브라우징 탐지
"""
import requests

def scan(target_url):
    result = {
        'name': 'Broken Access Control (접근 제어)',
        'category': 'OWASP A01',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': '모든 요청에 대해 서버 측 권한 검증, 최소 권한 원칙 적용',
        'details': ''
    }
    
    details = []
    
    # 1. IDOR (Insecure Direct Object Reference)
    details.append("[접근제어-1] IDOR 테스트")
    
    try:
        # 다른 사용자 ID로 접근 시도
        test_ids = [1, 2, 3, 999, 'admin', 'EMP001', 'EMP002']
        
        for user_id in test_ids:
            endpoints = [
                f"{target_url}/api/employees/{user_id}",
                f"{target_url}/api/employees/me?id={user_id}",
            ]
            
            for endpoint in endpoints:
                headers = {'X-Security-Mode': 'vulnerable'}
                resp = requests.get(endpoint, headers=headers, timeout=5)
                
                if resp.status_code == 200:
                    result['vulnerabilities'].append(f"IDOR: {endpoint}")
                    details.append(f"  ✗ {endpoint} - 접근 가능")
                    result['status'] = 'VULNERABLE'
                    break
            
            if result['status'] == 'VULNERABLE':
                break
                
    except:
        details.append("  • IDOR 테스트 실패")
    
    # 2. 파일 접근 제어
    details.append("\n[접근제어-2] 파일 접근 제어")
    
    try:
        file_endpoints = [
            f"{target_url}/api/teams/1/files",
            f"{target_url}/api/teams/2/files",
            f"{target_url}/api/teams/999/files",
        ]
        
        for endpoint in file_endpoints:
            headers = {'X-Security-Mode': 'vulnerable'}
            resp = requests.get(endpoint, headers=headers, timeout=5)
            
            if resp.status_code == 200:
                result['vulnerabilities'].append(f"타 팀 파일 접근 가능")
                details.append(f"  ✗ {endpoint} 접근 허용")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • 파일 접근 테스트 불가")
    
    # 3. 관리자 기능 접근
    details.append("\n[접근제어-3] 관리자 페이지 접근")
    
    admin_endpoints = [
        '/api/admin/users',
        '/api/admin/settings',
        '/admin',
        '/administrator',
    ]
    
    for endpoint in admin_endpoints:
        try:
            url = f"{target_url}{endpoint}"
            resp = requests.get(url, timeout=5)
            
            # 200이면 접근 가능 (취약)
            if resp.status_code == 200:
                result['vulnerabilities'].append(f"관리자 페이지 무인증 접근: {endpoint}")
                details.append(f"  ✗ {endpoint} - 인증 없이 접근")
                result['status'] = 'VULNERABLE'
                
        except:
            pass
    
    if result['status'] == 'SAFE':
        details.append("  ✓ 양호: 접근 제어 적절")
    
    result['details'] = '\n'.join(details)
    return result