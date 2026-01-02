"""
Command Injection 안전 버전 (Safety Version)

시스템에 실제 명령을 실행하지 않고, 시그니처 기반으로 취약점을 탐지합니다.
- 무해한 명령어만 사용 (ping, hostname 등)
- 시간 지연 기반 탐지
"""
import requests
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


def scan(target_url):
    result = {
        'name': 'Command Injection (안전 버전)',
        'category': 'Web Security',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': '입력값 화이트리스트, 명령어 직접 실행 금지',
        'details': ''
    }
    
    details = []
    
    # 안전한 페이로드 (무해한 명령, 시간 지연)
    SAFE_PAYLOADS = [
        # 시간 지연 기반 (무해)
        ('; sleep 2', 'sleep_unix'),
        ('| sleep 2', 'pipe_sleep'),
        ('`sleep 2`', 'backtick_sleep'),
        ('$(sleep 2)', 'subshell_sleep'),
        
        # Windows 시간 지연
        ('& ping -n 3 127.0.0.1', 'ping_windows'),
        ('| ping -c 3 127.0.0.1', 'ping_unix'),
        
        # 파이프라인 테스트 (무해한 출력)
        ('| echo CMDTEST', 'pipe_echo'),
        ('; echo CMDTEST', 'semicolon_echo'),
        ('`echo CMDTEST`', 'backtick_echo'),
    ]
    
    # 명령 실행 시그니처
    CMD_SIGNATURES = [
        'CMDTEST',  # 에코 테스트
        'root:',    # /etc/passwd
        'uid=',     # id 명령
        'Permission denied',  # 명령 실행 시도 흔적
        'command not found',
        'not recognized as',  # Windows
        '/bin/sh',
        '/bin/bash',
    ]
    
    try:
        details.append("[CMDi-Safe-1] Command Injection 탐지 (안전 모드)")
        details.append("  ※ 무해한 명령(echo, sleep, ping)만 사용\n")
        
        # URL 파라미터 추출
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            test_urls = [
                urljoin(target_url, '/ping?host=localhost'),
                urljoin(target_url, '/execute?cmd=test'),
                urljoin(target_url, '/api/run?command=test'),
            ]
        else:
            test_urls = [target_url]
        
        vulnerable_points = []
        
        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param_name, param_values in params.items():
                details.append(f"[테스트] 파라미터: {param_name}")
                
                # 정상 응답 시간
                try:
                    start = time.time()
                    normal_response = requests.get(url, timeout=10, verify=False)
                    normal_time = time.time() - start
                except:
                    continue
                
                for payload, payload_type in SAFE_PAYLOADS:
                    try:
                        test_params = {k: v[0] if v else '' for k, v in params.items()}
                        test_params[param_name] = (param_values[0] if param_values else 'test') + payload
                        
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                        
                        start = time.time()
                        response = requests.get(test_url, timeout=15, verify=False)
                        response_time = time.time() - start
                        
                        # 탐지 1: 시간 지연
                        if 'sleep' in payload_type or 'ping' in payload_type:
                            if response_time > normal_time + 1.5:
                                vulnerable_points.append({
                                    'param': param_name,
                                    'payload': payload_type,
                                    'method': 'time_based',
                                    'delay': response_time - normal_time
                                })
                                details.append(f"    ✗ 시간 기반 CMDi 감지: {response_time:.2f}초 지연")
                        
                        # 탐지 2: 시그니처
                        for sig in CMD_SIGNATURES:
                            if sig in response.text:
                                vulnerable_points.append({
                                    'param': param_name,
                                    'payload': payload_type,
                                    'method': 'signature',
                                    'signature': sig
                                })
                                details.append(f"    ✗ 시그니처 감지: {sig}")
                                break
                        
                    except requests.Timeout:
                        if 'sleep' in payload_type or 'ping' in payload_type:
                            details.append(f"    ✗ 타임아웃 (CMDi 가능)")
                    except Exception as e:
                        continue
        
        if vulnerable_points:
            result['status'] = 'VULNERABLE'
            result['vulnerabilities'] = [
                f"Command Injection: {v['param']} ({v['method']})"
                for v in vulnerable_points
            ]
            details.append(f"\n  총 {len(vulnerable_points)}개 취약점 발견")
        else:
            details.append("\n  ✓ Command Injection 취약점 미발견")
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
