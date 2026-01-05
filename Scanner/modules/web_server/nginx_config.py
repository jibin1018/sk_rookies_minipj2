"""
KISA 웹 서버 보안 가이드 - Nginx 보안 설정
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Nginx 웹서버 보안 설정',
        'category': 'KISA 웹서버 보안',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'Nginx 보안 설정 강화: 버전 숨김, 디렉터리 리스팅 차단, 안전한 설정',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file, timeout=10)
        
        # Nginx 설치 확인
        stdin, stdout, stderr = ssh.exec_command("which nginx 2>/dev/null")
        nginx_path = stdout.read().decode().strip()
        
        if not nginx_path:
            details.append("  [INFO] Nginx 웹서버가 설치되지 않음")
            result['status'] = 'N/A'
            result['details'] = '\n'.join(details)
            ssh.close()
            return result
        
        details.append(f"Nginx 경로: {nginx_path}")
        
        # Nginx 설정 파일 찾기
        stdin, stdout, stderr = ssh.exec_command("nginx -t 2>&1 | grep 'configuration file' | awk '{print $5}'")
        config_file = stdout.read().decode().strip()
        
        if not config_file:
            config_file = '/etc/nginx/nginx.conf'
        
        details.append(f"설정 파일: {config_file}")
        
        # 1. Nginx 버전 확인
        details.append("\n[Nginx-1] Nginx 버전 확인")
        
        stdin, stdout, stderr = ssh.exec_command("nginx -v 2>&1")
        nginx_version = stdout.read().decode().strip()
        
        if nginx_version:
            details.append(f"  현재 버전: {nginx_version}")
            
            # 버전 번호 추출
            import re
            version_match = re.search(r'nginx/(\d+\.\d+\.\d+)', nginx_version)
            if version_match:
                version = version_match.group(1)
                
                # 알려진 취약 버전
                vulnerable_versions = {
                    '1.6.': 'CVE-2013-4547 (매우 오래됨)',
                    '1.10.': '오래된 버전',
                }
                
                for vuln_ver, desc in vulnerable_versions.items():
                    if version.startswith(vuln_ver):
                        result['vulnerabilities'].append(f"취약한 Nginx 버전: {version}")
                        details.append(f"  ✗ 취약: {desc}")
                        result['status'] = 'VULNERABLE'
                        break
        
        # 2. 서버 버전 정보 숨김
        details.append("\n[Nginx-2] 서버 버전 정보 노출 차단")
        
        stdin, stdout, stderr = ssh.exec_command(f"grep -r 'server_tokens' {config_file} /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null")
        server_tokens = stdout.read().decode().strip()
        
        if 'server_tokens off' in server_tokens.lower():
            details.append("  ✓ 양호: server_tokens off")
        else:
            result['vulnerabilities'].append("Nginx 버전 정보 노출")
            details.append("  ✗ 취약: server_tokens off 미설정")
            result['status'] = 'VULNERABLE'
        
        # 3. 디렉터리 리스팅 차단
        details.append("\n[Nginx-3] 디렉터리 리스팅 차단 확인")
        
        stdin, stdout, stderr = ssh.exec_command(f"grep -r 'autoindex' {config_file} /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null")
        autoindex = stdout.read().decode().strip()
        
        if 'autoindex on' in autoindex and not autoindex.startswith('#'):
            result['vulnerabilities'].append("디렉터리 리스팅 활성화")
            details.append("  ✗ 취약: autoindex on")
            result['status'] = 'VULNERABLE'
        elif 'autoindex off' in autoindex:
            details.append("  ✓ 양호: autoindex off")
        else:
            details.append("  ✓ 양호: autoindex 설정 없음 (기본값: off)")
        
        # 4. 실행 사용자 확인
        details.append("\n[Nginx-4] Nginx 실행 사용자 확인")
        
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep nginx | grep -v grep | head -1 | awk '{print $1}'")
        nginx_user = stdout.read().decode().strip()
        
        if nginx_user in ['root']:
            result['vulnerabilities'].append("Nginx worker가 root로 실행 (마스터는 root 정상)")
            details.append(f"  ✗ 취약: worker 프로세스가 root 권한")
            result['status'] = 'VULNERABLE'
        elif nginx_user:
            details.append(f"  ✓ 양호: {nginx_user} 권한으로 실행")
            
            # user 지시자 확인
            stdin, stdout, stderr = ssh.exec_command(f"grep '^user' {config_file}")
            user_config = stdout.read().decode().strip()
            if user_config:
                details.append(f"    설정: {user_config}")
        
        # 5. 클라이언트 요청 크기 제한
        details.append("\n[Nginx-5] 클라이언트 요청 크기 제한")
        
        stdin, stdout, stderr = ssh.exec_command(f"grep -r 'client_max_body_size' {config_file} /etc/nginx/conf.d/ 2>/dev/null")
        client_max = stdout.read().decode().strip()
        
        if client_max and not client_max.startswith('#'):
            details.append(f"  ✓ 양호: {client_max}")
        else:
            result['vulnerabilities'].append("클라이언트 요청 크기 제한 없음")
            details.append("  ⚠ 주의: client_max_body_size 미설정 (기본: 1m)")
        
        # 6. 타임아웃 설정
        details.append("\n[Nginx-6] 타임아웃 설정 확인")
        
        timeout_directives = [
            'client_body_timeout',
            'client_header_timeout',
            'keepalive_timeout',
            'send_timeout'
        ]
        
        for directive in timeout_directives:
            stdin, stdout, stderr = ssh.exec_command(f"grep -r '{directive}' {config_file} /etc/nginx/conf.d/ 2>/dev/null | grep -v '#'")
            timeout_val = stdout.read().decode().strip()
            
            if timeout_val:
                details.append(f"  ✓ {directive}: {timeout_val.split(':')[-1].strip()}")
            else:
                details.append(f"  • {directive}: 기본값 사용")
        
        # 7. 버퍼 오버플로우 방지
        details.append("\n[Nginx-7] 버퍼 크기 제한 확인")
        
        buffer_directives = {
            'client_body_buffer_size': '128k',
            'client_header_buffer_size': '1k',
            'large_client_header_buffers': '4 8k',
        }
        
        for directive, recommended in buffer_directives.items():
            stdin, stdout, stderr = ssh.exec_command(f"grep -r '{directive}' {config_file} /etc/nginx/conf.d/ 2>/dev/null | grep -v '#'")
            buffer_val = stdout.read().decode().strip()
            
            if buffer_val:
                details.append(f"  ✓ {directive}: 설정됨")
            else:
                details.append(f"  • {directive}: 기본값 (권장: {recommended})")
        
        # 8. SSL/TLS 설정 확인
        details.append("\n[Nginx-8] SSL/TLS 보안 설정")
        
        stdin, stdout, stderr = ssh.exec_command(f"grep -r 'ssl_protocols' {config_file} /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null | grep -v '#'")
        ssl_protocols = stdout.read().decode().strip()
        
        if ssl_protocols:
            details.append(f"  SSL Protocols: {ssl_protocols.split(':')[-1].strip()}")
            
            # 취약한 프로토콜 확인
            if 'SSLv2' in ssl_protocols or 'SSLv3' in ssl_protocols or 'TLSv1 ' in ssl_protocols:
                result['vulnerabilities'].append("취약한 SSL/TLS 프로토콜 사용")
                details.append("  ✗ 취약: SSLv2/SSLv3/TLSv1.0 사용 중")
                result['status'] = 'VULNERABLE'
            else:
                details.append("  ✓ 양호: 안전한 TLS 버전 사용")
        else:
            details.append("  • SSL 설정 없음 또는 기본값 사용")
        
        # SSL 암호화 스위트
        stdin, stdout, stderr = ssh.exec_command(f"grep -r 'ssl_ciphers' {config_file} /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null | grep -v '#'")
        ssl_ciphers = stdout.read().decode().strip()
        
        if ssl_ciphers:
            details.append(f"  SSL Ciphers: 설정됨")
        
        # 9. 보안 헤더 확인
        details.append("\n[Nginx-9] 보안 헤더 설정 확인")
        
        security_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
        ]
        
        for header in security_headers:
            stdin, stdout, stderr = ssh.exec_command(
                f"grep -r 'add_header.*{header}' {config_file} /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null | grep -v '#'"
            )
            header_config = stdout.read().decode().strip()
            
            if header_config:
                details.append(f"  ✓ {header}: 설정됨")
            else:
                result['vulnerabilities'].append(f"{header} 헤더 미설정")
                details.append(f"  ⚠ {header}: 미설정")
        
        # 10. 접근 로그 설정
        details.append("\n[Nginx-10] 접근 로그 설정 확인")
        
        stdin, stdout, stderr = ssh.exec_command(f"grep -r 'access_log' {config_file} /etc/nginx/conf.d/ 2>/dev/null | grep -v '#'")
        access_log = stdout.read().decode().strip()
        
        if access_log and 'access_log off' not in access_log:
            details.append(f"  ✓ 양호: 접근 로그 활성화")
        elif 'access_log off' in access_log:
            result['vulnerabilities'].append("접근 로그 비활성화")
            details.append("  ✗ 취약: access_log off")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  • 기본 로그 설정 사용")
        
        # 11. 메소드 제한
        details.append("\n[Nginx-11] HTTP 메소드 제한 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            f"grep -r 'limit_except' {config_file} /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null"
        )
        limit_except = stdout.read().decode().strip()
        
        if limit_except:
            details.append(f"  ✓ 양호: HTTP 메소드 제한 설정")
        else:
            details.append("  ⚠ 주의: limit_except 설정 없음")
        
        # 12. 숨겨진 파일 접근 차단
        details.append("\n[Nginx-12] 숨겨진 파일(.git, .env) 접근 차단")
        
        stdin, stdout, stderr = ssh.exec_command(
            f"grep -r 'location.*\\.git' {config_file} /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null"
        )
        hidden_files = stdout.read().decode().strip()
        
        if hidden_files and 'deny all' in hidden_files:
            details.append("  ✓ 양호: 숨겨진 파일 접근 차단")
        else:
            result['vulnerabilities'].append("숨겨진 파일 접근 차단 없음")
            details.append("  ⚠ .git, .env 등 접근 차단 설정 권장")
        
        ssh.close()
        
    except paramiko.AuthenticationException:
        details.append("  [ERROR] SSH 인증 실패")
        result['status'] = 'ERROR'
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result