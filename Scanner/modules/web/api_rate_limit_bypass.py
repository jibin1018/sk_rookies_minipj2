"""
API Rate Limit 우회 점검

API Rate Limiting 설정 및 우회 가능성을 점검합니다.
"""
import requests
import time
from urllib.parse import urljoin


def scan(target_url):
    result = {
        'name': 'API Rate Limit 점검',
        'category': 'API Security',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'Rate Limiting 적용, 분산 환경에서 동기화',
        'details': ''
    }
    
    details = []
    
    # 우회 헤더
    BYPASS_HEADERS = [
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Real-IP': '127.0.0.1'},
        {'X-Originating-IP': '127.0.0.1'},
        {'X-Remote-IP': '127.0.0.1'},
        {'X-Client-IP': '127.0.0.1'},
        {'X-Forwarded-Host': 'localhost'},
        {'True-Client-IP': '127.0.0.1'},
    ]
    
    try:
        details.append("[RateLimit-1] Rate Limiting 분석\n")
        
        # 정상 요청으로 기준 확인
        response = requests.get(target_url, timeout=10, verify=False)
        
        # Rate Limit 관련 헤더 확인
        limit_headers = {
            'X-RateLimit-Limit': response.headers.get('X-RateLimit-Limit'),
            'X-RateLimit-Remaining': response.headers.get('X-RateLimit-Remaining'),
            'X-RateLimit-Reset': response.headers.get('X-RateLimit-Reset'),
            'Retry-After': response.headers.get('Retry-After'),
            'RateLimit-Limit': response.headers.get('RateLimit-Limit'),
        }
        
        has_rate_limit = any(limit_headers.values())
        
        if has_rate_limit:
            details.append("  ✓ Rate Limit 헤더 감지")
            for header, value in limit_headers.items():
                if value:
                    details.append(f"    {header}: {value}")
        else:
            details.append("  ⚠ Rate Limit 헤더 없음")
        
        # 빠른 연속 요청 테스트 (10회)
        details.append("\n[RateLimit-2] 연속 요청 테스트")
        
        blocked = False
        responses = []
        
        for i in range(10):
            try:
                resp = requests.get(target_url, timeout=5, verify=False)
                responses.append(resp.status_code)
                
                if resp.status_code == 429:
                    blocked = True
                    details.append(f"  요청 {i+1}: 429 Too Many Requests")
                    break
                elif resp.status_code != 200:
                    details.append(f"  요청 {i+1}: {resp.status_code}")
                    
            except:
                continue
        
        if blocked:
            details.append("  ✓ Rate Limiting 작동")
        else:
            details.append(f"  ⚠ 10회 요청 모두 허용됨")
            if not has_rate_limit:
                result['vulnerabilities'].append("Rate Limiting 미설정")
        
        # 우회 테스트
        details.append("\n[RateLimit-3] 우회 가능성 테스트")
        
        bypass_possible = []
        
        for headers in BYPASS_HEADERS:
            header_name = list(headers.keys())[0]
            
            try:
                # 다른 IP로 위장
                bypass_headers = headers.copy()
                bypass_headers[header_name] = f"192.168.1.{hash(header_name) % 255}"
                
                resp = requests.get(
                    target_url,
                    headers=bypass_headers,
                    timeout=5,
                    verify=False
                )
                
                # 원래 차단되었는데 우회되면 취약
                if blocked and resp.status_code == 200:
                    bypass_possible.append(header_name)
                    details.append(f"  ✗ 우회 가능: {header_name}")
                    
            except:
                continue
        
        if bypass_possible:
            result['status'] = 'VULNERABLE'
            result['vulnerabilities'].extend([
                f"Rate Limit 우회: {h}" for h in bypass_possible
            ])
        
        # 요약
        details.append("\n[RateLimit-4] 보안 요약")
        
        if result['vulnerabilities']:
            details.append(f"\n  취약점: {len(result['vulnerabilities'])}개")
        else:
            if has_rate_limit:
                details.append("\n  ✓ Rate Limiting 정상 작동")
            else:
                result['status'] = 'VULNERABLE'
                details.append("\n  ⚠ Rate Limiting 미적용")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
