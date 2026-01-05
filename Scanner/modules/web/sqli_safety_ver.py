"""
SQL Injection 안전 버전 (Safety Version)

데이터베이스에 피해를 주지 않는 Read-Only 방식으로 SQLi 취약점을 탐지합니다.
- 실제 데이터 변조 없음
- 시간 기반 탐지 (응답 지연)
- 에러 기반 탐지 (에러 메시지 분석)
"""
import requests
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


def scan(target_url):
    result = {
        'name': 'SQL Injection (안전 버전)',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': '매개변수화된 쿼리 사용, ORM 활용, 입력값 검증',
        'details': ''
    }
    
    details = []
    
    # Read-Only 페이로드 (데이터 변조 없음)
    SAFE_PAYLOADS = [
        # 에러 기반 탐지 (구문 오류 유발)
        ("'", "single_quote"),
        ('"', "double_quote"),
        ("' OR '1'='1", "or_condition"),
        ("1' AND '1'='1", "and_condition"),
        
        # 시간 기반 탐지 (SLEEP 함수로 응답 지연 확인)
        ("1' AND SLEEP(2)--", "mysql_sleep"),
        ("1'; WAITFOR DELAY '00:00:02'--", "mssql_sleep"),
        ("1' AND pg_sleep(2)--", "postgresql_sleep"),
        
        # 주석 기반 탐지
        ("1--", "comment_dash"),
        ("1/*", "comment_block"),
    ]
    
    # SQL 에러 시그니처
    SQL_ERRORS = [
        'sql syntax', 'mysql', 'sqlite', 'postgresql', 'oracle',
        'syntax error', 'unclosed quotation', 'unterminated string',
        'sql server', 'odbc', 'jdbc', 'ORA-', 'PLS-',
        'microsoft ole db', 'warning: mysql', 'valid mysql result',
        'pg_query', 'supplied argument is not a valid',
    ]
    
    try:
        details.append("[SQLi-Safe-1] SQL Injection 탐지 (안전 모드)")
        details.append("  ※ Read-Only 페이로드만 사용, 데이터 변조 없음\n")
        
        # URL 파라미터 추출
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            # 파라미터 없으면 일반적인 테스트 경로 시도
            test_urls = [
                urljoin(target_url, '/search?q=test'),
                urljoin(target_url, '/api/v1/search?keyword=test'),
                urljoin(target_url, '/?id=1'),
            ]
        else:
            test_urls = [target_url]
        
        vulnerable_points = []
        
        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param_name, param_values in params.items():
                details.append(f"[테스트] 파라미터: {param_name}")
                
                # 정상 응답 시간 측정
                try:
                    start = time.time()
                    normal_response = requests.get(url, timeout=10, verify=False)
                    normal_time = time.time() - start
                    normal_length = len(normal_response.text)
                except:
                    continue
                
                for payload, payload_type in SAFE_PAYLOADS:
                    try:
                        # 페이로드 삽입
                        test_params = {k: v[0] if v else '' for k, v in params.items()}
                        test_params[param_name] = param_values[0] + payload if param_values else payload
                        
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                        
                        start = time.time()
                        response = requests.get(test_url, timeout=15, verify=False)
                        response_time = time.time() - start
                        
                        # 탐지 방법 1: 에러 메시지
                        for error in SQL_ERRORS:
                            if error.lower() in response.text.lower():
                                vulnerable_points.append({
                                    'param': param_name,
                                    'payload': payload_type,
                                    'method': 'error_based'
                                })
                                details.append(f"    ✗ 에러 기반 SQLi 감지: {error}")
                                break
                        
                        # 탐지 방법 2: 시간 지연 (SLEEP 페이로드)
                        if 'sleep' in payload_type and response_time > normal_time + 1.5:
                            vulnerable_points.append({
                                'param': param_name,
                                'payload': payload_type,
                                'method': 'time_based',
                                'delay': response_time - normal_time
                            })
                            details.append(f"    ✗ 시간 기반 SQLi 감지: {response_time:.2f}초 지연")
                        
                        # 탐지 방법 3: 응답 길이 변화
                        if abs(len(response.text) - normal_length) > 500:
                            if 'or_condition' in payload_type or 'and_condition' in payload_type:
                                details.append(f"    ⚠ 응답 변화 감지 (길이: {normal_length} → {len(response.text)})")
                        
                    except requests.Timeout:
                        # 타임아웃도 시간 기반 탐지 힌트
                        if 'sleep' in payload_type:
                            details.append(f"    ✗ 타임아웃 발생 (시간 기반 SQLi 가능)")
                    except Exception as e:
                        continue
        
        if vulnerable_points:
            result['status'] = 'VULNERABLE'
            result['vulnerabilities'] = [
                f"SQLi 취약점 발견: {v['param']} ({v['method']})"
                for v in vulnerable_points
            ]
            details.append(f"\n  총 {len(vulnerable_points)}개 취약점 발견")
        else:
            details.append("\n  ✓ SQL Injection 취약점 미발견")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
