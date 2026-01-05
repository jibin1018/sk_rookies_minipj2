"""
CORS 상세 분석

Cross-Origin Resource Sharing 설정을 상세히 분석합니다.
"""
import requests


def scan(target_url):
    result = {
        'name': 'CORS 상세 분석',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '신뢰할 수 있는 Origin만 허용, 와일드카드 사용 금지',
        'details': ''
    }
    
    details = []
    
    # 테스트 Origin 목록
    TEST_ORIGINS = [
        ('https://evil.com', '악성 도메인'),
        ('null', 'null Origin'),
        ('https://target.com.evil.com', '서브도메인 위장'),
        ('http://' + target_url.split('//')[1].split('/')[0], 'HTTP 다운그레이드'),
    ]
    
    try:
        details.append("[CORS-1] CORS 헤더 분석\n")
        
        # 기본 요청
        response = requests.get(target_url, timeout=10, verify=False)
        
        acao = response.headers.get('Access-Control-Allow-Origin')
        acac = response.headers.get('Access-Control-Allow-Credentials')
        acam = response.headers.get('Access-Control-Allow-Methods')
        acah = response.headers.get('Access-Control-Allow-Headers')
        
        if acao:
            details.append(f"  Allow-Origin: {acao}")
        if acac:
            details.append(f"  Allow-Credentials: {acac}")
        if acam:
            details.append(f"  Allow-Methods: {acam}")
        if acah:
            details.append(f"  Allow-Headers: {acah}")
        
        if not acao:
            details.append("  CORS 헤더 없음 (Same-Origin만 허용)")
            result['details'] = '\n'.join(details)
            return result
        
        # 와일드카드 검사
        if acao == '*':
            details.append("\n  ⚠ 와일드카드(*) 사용")
            if acac and acac.lower() == 'true':
                result['vulnerabilities'].append("와일드카드 + Credentials 허용")
                result['status'] = 'VULNERABLE'
                details.append("  ✗ Credentials와 함께 사용 (매우 위험)")
            else:
                details.append("  Credentials 없음 (일부 안전)")
        
        # Origin 반영 테스트
        details.append("\n[CORS-2] Origin 반영 테스트")
        
        for origin, desc in TEST_ORIGINS:
            try:
                headers = {'Origin': origin}
                response = requests.get(
                    target_url,
                    headers=headers,
                    timeout=5,
                    verify=False
                )
                
                reflected_origin = response.headers.get('Access-Control-Allow-Origin')
                allows_creds = response.headers.get('Access-Control-Allow-Credentials', '').lower() == 'true'
                
                if reflected_origin == origin:
                    details.append(f"\n  ✗ {desc} 반영됨")
                    details.append(f"    Origin: {origin}")
                    
                    if allows_creds:
                        result['vulnerabilities'].append(f"CORS 반영 + Credentials: {desc}")
                        result['status'] = 'VULNERABLE'
                        result['severity'] = 'CRITICAL'
                        details.append(f"    Credentials: 허용 (매우 위험!)")
                    else:
                        result['vulnerabilities'].append(f"CORS Origin 반영: {desc}")
                        if result['status'] == 'SAFE':
                            result['status'] = 'VULNERABLE'
                        details.append(f"    Credentials: 미허용")
                
                elif reflected_origin == '*' and origin != 'null':
                    details.append(f"\n  ⚠ {desc}: 와일드카드 응답")
                
            except Exception as e:
                continue
        
        # Preflight 테스트
        details.append("\n[CORS-3] Preflight 분석")
        
        try:
            preflight_headers = {
                'Origin': 'https://test.com',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'X-Custom-Header',
            }
            
            response = requests.options(
                target_url,
                headers=preflight_headers,
                timeout=5,
                verify=False
            )
            
            if response.status_code == 200:
                allowed_methods = response.headers.get('Access-Control-Allow-Methods', '')
                allowed_headers = response.headers.get('Access-Control-Allow-Headers', '')
                max_age = response.headers.get('Access-Control-Max-Age', '')
                
                details.append(f"  Methods: {allowed_methods or 'N/A'}")
                details.append(f"  Headers: {allowed_headers or 'N/A'}")
                details.append(f"  Max-Age: {max_age or 'N/A'}")
                
                # 위험한 메서드 확인
                dangerous_methods = ['PUT', 'DELETE', 'PATCH']
                for method in dangerous_methods:
                    if method in allowed_methods.upper():
                        details.append(f"  ⚠ {method} 허용됨")
            else:
                details.append(f"  Preflight 응답: {response.status_code}")
                
        except Exception as e:
            details.append(f"  Preflight 테스트 실패: {str(e)}")
        
        # 요약
        details.append("\n[CORS-4] 보안 요약")
        
        if result['vulnerabilities']:
            details.append(f"\n  취약점: {len(result['vulnerabilities'])}개")
            for vuln in result['vulnerabilities']:
                details.append(f"    - {vuln}")
        else:
            details.append("\n  ✓ CORS 설정 양호")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
