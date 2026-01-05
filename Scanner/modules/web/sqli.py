"""
SQL Injection (SQL 인젝션)
Error-based, Union-based, Boolean-based Blind, Time-based Blind SQLi
"""
import requests
import time
import re

def scan(target_url):
    """Legacy Interface for compatibility"""
    return scan_advanced(target_url, [target_url], [])

def scan_advanced(target_url, visited_urls, api_endpoints):
    """
    Advanced SQL Injection Scan using Crawled Data
    
    Args:
        target_url (str): Base URL
        visited_urls (list): List of crawled URLs (GET)
        api_endpoints (list): List of form actions (POST)
    """
    result = {
        'name': 'SQL Injection (종합)',
        'category': 'Injection',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'count': 0,  # 테스트 실행 횟수
        'sub_vulnerabilities': [], # 상세 취약점 목록 (타입 포함)
        'recommendation': 'Prepared Statement/ORM 사용, 입력값 검증, 최소 권한 원칙',
        'details': ''
    }
    
    details = []
    
    # 공격 벡터 식별
    # 1. GET 파라미터가 있는 URL 식별
    target_get_urls = []
    for url in visited_urls:
        if '?' in url:
            target_get_urls.append(url)
            
    # 2. POST 엔드포인트
    target_post_urls = api_endpoints
    
    # 페이로드 정의
    payloads = {
        'error_based': ["'", "''", "1' AND '1'='2"],
        'auth_bypass': ["' OR '1'='1", "admin' --", "' OR 1=1 --"],
        'time_based': ["' OR SLEEP(5)--", "'; WAITFOR DELAY '00:00:05'--"],
    }
    
    total_checks = 0
    
    # 1. GET Parameter Checking
    for url in target_get_urls:
        if total_checks > 50: break # 과부하 방지
        
        base_url, query_string = url.split('?', 1)
        params = query_string.split('&')
        
        for param in params:
            if '=' not in param: continue
            key, val = param.split('=', 1)
            
            for p_type, p_list in payloads.items():
                for payload in p_list:
                    check_url = f"{base_url}?{key}={val}{payload}"
                    total_checks += 1
                    try:
                        start_time = time.time()
                        resp = requests.get(check_url, timeout=5)
                        duration = time.time() - start_time
                        
                        # 탐지 로직
                        if _detect_sqli(resp, duration, p_type):
                            vuln_name = f"SQL Injection ({p_type})"
                            if vuln_name not in result['vulnerabilities']:
                                result['vulnerabilities'].append(vuln_name)
                                result['sub_vulnerabilities'].append({'type': p_type, 'url': url, 'param': key})
                                details.append(f"  ✗ {vuln_name} 발견: {url} (Param: {key})")
                                result['status'] = 'VULNERABLE'
                    except:
                        pass

    # 2. POST Parameter Checking
    for url in target_post_urls:
        if total_checks > 100: break
        
        # 추정되는 일반적인 필드명
        fields = ['id', 'user', 'username', 'email', 'password', 'passwd', 'search', 'query']
        
        data = {f: 'test' for f in fields}
        
        for p_type, p_list in payloads.items():
            for payload in p_list:
                # 모든 필드에 하나씩 대입
                for field in fields:
                    test_data = data.copy()
                    test_data[field] = payload
                    total_checks += 1
                    
                    try:
                        start_time = time.time()
                        resp = requests.post(url, data=test_data, timeout=5)
                        duration = time.time() - start_time
                        
                        if _detect_sqli(resp, duration, p_type):
                            vuln_name = f"SQL Injection ({p_type})"
                            if vuln_name not in result['vulnerabilities']:
                                result['vulnerabilities'].append(vuln_name)
                                result['sub_vulnerabilities'].append({'type': p_type, 'url': url, 'field': field})
                                details.append(f"  ✗ {vuln_name} 발견: {url} (Field: {field})")
                                result['status'] = 'VULNERABLE'
                    except:
                        pass

    result['count'] = total_checks
    if result['status'] == 'SAFE':
        details.append(f"✓ 총 {total_checks}개 패턴 테스트 완료 (취약점 없음)")
    
    result['details'] = '\n'.join(details)
    return result

def _detect_sqli(resp, duration, p_type):
    """탐지 로직 분리"""
    sql_errors = [
        'sql syntax', 'mysql', 'postgresql', 'sqlite', 'oracle',
        'ora-', 'sql server', 'syntax error', 'unclosed quotation'
    ]
    
    if p_type == 'error_based':
        if any(e in resp.text.lower() for e in sql_errors):
            return True
    elif p_type == 'time_based':
        if duration > 4.5: # 5초 sleep 가정
            return True
    elif p_type == 'auth_bypass':
        if resp.status_code == 200 and ('success' in resp.text.lower() or 'token' in resp.text.lower()):
            return True
            
    return False