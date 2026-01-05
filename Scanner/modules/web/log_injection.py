"""
로그 인젝션 점검

로그에 악성 데이터를 주입하여 로그 위조 가능성을 탐지합니다.
안전 모드: 무해한 마커만 사용
"""
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


def scan(target_url):
    result = {
        'name': '로그 인젝션',
        'category': 'Logging Security',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '로그 출력 전 입력값 검증 및 인코딩',
        'details': ''
    }
    
    details = []
    
    # 안전한 로그 인젝션 테스트 페이로드
    SAFE_PAYLOADS = [
        # 줄바꿈으로 가짜 로그 엔트리
        ('test%0aFAKE_LOG_ENTRY', 'newline_crlf'),
        ('test%0d%0aFAKE_LOG_ENTRY', 'crlf'),
        ('test\nFAKE_LOG_ENTRY', 'newline'),
        
        # 탭 문자로 필드 조작
        ('test%09admin%09SUCCESS', 'tab_inject'),
        
        # ANSI 이스케이프 (터미널 로그)
        ('test%1b[31mRED%1b[0m', 'ansi_color'),
        
        # 로그 형식 주입
        ('[ERROR] Fake error message', 'log_format'),
        ('test" level="ERROR"', 'json_log_inject'),
    ]
    
    try:
        details.append("[LogInject-1] 로그 인젝션 탐지 (안전 모드)\n")
        details.append("  ※ 무해한 페이로드로 인젝션 가능성만 탐지\n")
        
        # URL 파라미터 추출
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        
        # 테스트 엔드포인트
        test_endpoints = []
        
        if params:
            test_endpoints.append(target_url)
        
        # 일반적인 로그 발생 엔드포인트
        log_endpoints = [
            '?search=test',
            '?query=test',
            '?username=test',
            '?action=test',
        ]
        
        for ep in log_endpoints:
            test_endpoints.append(target_url.rstrip('/') + ep)
        
        injectable_params = []
        
        for url in test_endpoints[:3]:  # 최대 3개
            parsed_url = urlparse(url)
            url_params = parse_qs(parsed_url.query)
            
            if not url_params:
                continue
            
            details.append(f"[테스트] {parsed_url.path}")
            
            for param_name in url_params.keys():
                for payload, payload_type in SAFE_PAYLOADS[:4]:  # 최대 4개
                    try:
                        test_params = {k: v[0] for k, v in url_params.items()}
                        test_params[param_name] = payload
                        
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, safe='')}"
                        
                        response = requests.get(test_url, timeout=5, verify=False)
                        
                        # 응답에서 페이로드 반영 확인 (간접적 확인)
                        # 실제 로그는 확인 불가, 응답 기반 추론
                        
                        # 일반적인 에러 응답이 아닌 경우
                        if response.status_code == 200:
                            # User-Agent를 통한 로그 인젝션 테스트
                            inject_headers = {
                                'User-Agent': 'Mozilla/5.0 FAKE_LOG_ENTRY',
                                'Referer': 'http://evil.com%0d%0aFAKE_LOG',
                            }
                            
                            resp2 = requests.get(
                                url,
                                headers=inject_headers,
                                timeout=5,
                                verify=False
                            )
                            
                            # 성공적으로 처리되면 잠재적 취약
                            if resp2.status_code == 200:
                                injectable_params.append({
                                    'param': param_name,
                                    'type': payload_type,
                                    'location': 'header'
                                })
                                break
                        
                    except:
                        continue
        
        # User-Agent 로그 인젝션 테스트
        details.append("\n[LogInject-2] User-Agent 헤더 테스트")
        
        try:
            # 줄바꿈 포함 User-Agent
            test_ua = "Mozilla/5.0\r\nFake-Header: Injected"
            response = requests.get(
                target_url,
                headers={'User-Agent': test_ua},
                timeout=5,
                verify=False
            )
            
            if response.status_code == 200:
                details.append("  ⚠ 특수문자 포함 User-Agent 허용됨")
                result['vulnerabilities'].append("User-Agent 로그 인젝션 가능")
            else:
                details.append("  ✓ 특수문자 User-Agent 차단됨")
                
        except:
            details.append("  테스트 실패")
        
        # 요약
        details.append("\n[LogInject-3] 보안 요약")
        
        if result['vulnerabilities']:
            result['status'] = 'VULNERABLE'
            details.append(f"\n  취약점: {len(result['vulnerabilities'])}개")
            details.append("    로그 위조 공격에 취약할 수 있음")
        else:
            details.append("\n  ✓ 로그 인젝션 취약점 미발견")
            details.append("    ※ 서버 로그 직접 확인 권장")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
