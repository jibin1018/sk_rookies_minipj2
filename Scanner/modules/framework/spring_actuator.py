"""
Spring Boot Actuator 노출 점검

Spring Boot Actuator가 외부에 노출되어 있으면 민감한 정보가 유출될 수 있음
"""
import requests
from urllib.parse import urljoin


def scan(target_url):
    result = {
        'name': 'Spring Actuator 노출 점검',
        'category': 'Framework Security',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'Actuator 엔드포인트를 내부망으로 제한하거나 인증 적용',
        'details': ''
    }
    
    details = []
    
    # Actuator 엔드포인트 목록
    actuator_endpoints = [
        '/actuator',
        '/actuator/health',
        '/actuator/info',
        '/actuator/env',
        '/actuator/beans',
        '/actuator/configprops',
        '/actuator/mappings',
        '/actuator/metrics',
        '/actuator/heapdump',
        '/actuator/threaddump',
        '/actuator/loggers',
        '/actuator/shutdown',
        # Spring Boot 1.x 경로
        '/health',
        '/info',
        '/env',
        '/beans',
        '/mappings',
        '/trace',
        '/dump',
    ]
    
    # 민감한 엔드포인트
    sensitive_endpoints = [
        '/actuator/env',
        '/actuator/heapdump',
        '/actuator/configprops',
        '/actuator/shutdown',
        '/env',
        '/dump',
    ]
    
    found_endpoints = []
    sensitive_found = []
    
    details.append("[Spring-1] Actuator 엔드포인트 스캔")
    
    try:
        for endpoint in actuator_endpoints:
            url = urljoin(target_url, endpoint)
            try:
                response = requests.get(url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    found_endpoints.append(endpoint)
                    
                    if endpoint in sensitive_endpoints:
                        sensitive_found.append(endpoint)
                        
            except requests.RequestException:
                continue
        
        if found_endpoints:
            details.append(f"  발견된 Actuator 엔드포인트: {len(found_endpoints)}개")
            for ep in found_endpoints[:10]:
                details.append(f"    ✓ {ep}")
            
            if sensitive_found:
                result['status'] = 'VULNERABLE'
                result['severity'] = 'CRITICAL'
                result['vulnerabilities'].append(
                    f"민감한 Actuator 노출: {', '.join(sensitive_found)}"
                )
                details.append(f"\n  ✗ 민감 엔드포인트 노출:")
                for ep in sensitive_found:
                    details.append(f"    - {ep}")
            else:
                details.append("\n  ⚠ Actuator 노출됨 (민감 정보는 없음)")
                result['status'] = 'VULNERABLE'
                result['severity'] = 'MEDIUM'
                result['vulnerabilities'].append("Actuator 엔드포인트 외부 노출")
        else:
            details.append("  ✓ Actuator 엔드포인트 미노출")
        
        # Spring 에러 페이지 확인
        details.append("\n[Spring-2] Spring 에러 페이지 정보 노출")
        
        error_url = urljoin(target_url, '/error')
        try:
            response = requests.get(error_url, timeout=5, verify=False)
            if 'Whitelabel Error Page' in response.text:
                details.append("  ⚠ Spring 기본 에러 페이지 노출")
                result['vulnerabilities'].append("Spring Whitelabel 에러 페이지 노출")
                if result['status'] == 'SAFE':
                    result['status'] = 'VULNERABLE'
                    result['severity'] = 'LOW'
        except requests.RequestException:
            pass
        
        # JSESSIONID 쿠키 확인
        details.append("\n[Spring-3] 세션 쿠키 보안")
        
        try:
            response = requests.get(target_url, timeout=5, verify=False)
            cookies = response.cookies
            
            for cookie in cookies:
                if 'jsessionid' in cookie.name.lower():
                    if not cookie.secure:
                        details.append("  ⚠ JSESSIONID Secure 플래그 없음")
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        details.append("  ⚠ JSESSIONID HttpOnly 플래그 없음")
                    break
        except requests.RequestException:
            pass
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
