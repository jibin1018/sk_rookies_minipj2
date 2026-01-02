"""
KISA WAS 보안 가이드 - Tomcat 보안 설정
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'WAS-01~WAS-10: Tomcat 보안 설정',
        'category': 'KISA WAS 보안',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'Tomcat 보안 강화: 기본 계정 제거, 불필요한 앱 삭제, 에러 페이지 커스터마이징',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file, timeout=10)
        
        # Tomcat 설치 확인
        stdin, stdout, stderr = ssh.exec_command(
            "ps aux | grep tomcat | grep -v grep | head -1"
        )
        tomcat_process = stdout.read().decode().strip()
        
        if not tomcat_process:
            details.append("  [INFO] Tomcat이 실행되고 있지 않음")
            result['status'] = 'N/A'
            result['details'] = '\n'.join(details)
            ssh.close()
            return result
        
        details.append("Tomcat 프로세스 발견")
        
        # Tomcat 홈 디렉터리 찾기
        stdin, stdout, stderr = ssh.exec_command(
            "find /opt /usr/local /var/lib -name 'catalina.sh' 2>/dev/null | head -1 | xargs dirname | xargs dirname"
        )
        tomcat_home = stdout.read().decode().strip()
        
        if not tomcat_home:
            details.append("  [ERROR] Tomcat 홈 디렉터리를 찾을 수 없음")
            result['status'] = 'ERROR'
            result['details'] = '\n'.join(details)
            ssh.close()
            return result
        
        details.append(f"Tomcat 홈: {tomcat_home}")
        
        # 1. WAS-01: 기본 계정 제거
        details.append("\n[WAS-01] Tomcat 기본 계정 확인")
        
        tomcat_users_file = f"{tomcat_home}/conf/tomcat-users.xml"
        stdin, stdout, stderr = ssh.exec_command(f"cat {tomcat_users_file} 2>/dev/null")
        tomcat_users = stdout.read().decode()
        
        if tomcat_users:
            # 주석 제거하고 실제 사용자만 확인
            import re
            users = re.findall(r'<user\s+username="([^"]+)"', tomcat_users)
            
            default_users = ['admin', 'tomcat', 'manager', 'role1', 'both']
            found_default = [u for u in users if u in default_users]
            
            if found_default:
                result['vulnerabilities'].append(f"기본 계정 존재: {', '.join(found_default)}")
                details.append(f"  ✗ 취약: {', '.join(found_default)}")
                result['status'] = 'VULNERABLE'
            else:
                details.append(f"  ✓ 양호: 기본 계정 없음 (사용자: {len(users)}명)")
        else:
            details.append("  • tomcat-users.xml 파일 없음")
        
        # 2. WAS-02: 불필요한 기본 애플리케이션 제거
        details.append("\n[WAS-02] 기본 애플리케이션 확인")
        
        webapps_dir = f"{tomcat_home}/webapps"
        stdin, stdout, stderr = ssh.exec_command(f"ls -1 {webapps_dir} 2>/dev/null")
        webapps = stdout.read().decode().strip()
        
        if webapps:
            default_apps = ['docs', 'examples', 'host-manager', 'manager', 'ROOT']
            found_apps = [app for app in webapps.split('\n') if app in default_apps]
            
            if found_apps:
                result['vulnerabilities'].append(f"기본 애플리케이션 존재: {', '.join(found_apps)}")
                details.append(f"  ✗ 취약: {', '.join(found_apps)}")
                result['status'] = 'VULNERABLE'
            else:
                details.append(f"  ✓ 양호: 기본 앱 제거됨")
        else:
            details.append("  • webapps 디렉터리 확인 불가")
        
        # 3. WAS-03: 디렉터리 리스팅 차단
        details.append("\n[WAS-03] 디렉터리 리스팅 차단 확인")
        
        web_xml = f"{tomcat_home}/conf/web.xml"
        stdin, stdout, stderr = ssh.exec_command(f"grep -A 5 'default' {web_xml} | grep 'listings'")
        listings = stdout.read().decode().strip()
        
        if 'true' in listings.lower():
            result['vulnerabilities'].append("디렉터리 리스팅 활성화")
            details.append("  ✗ 취약: listings = true")
            result['status'] = 'VULNERABLE'
        elif 'false' in listings.lower():
            details.append("  ✓ 양호: listings = false")
        else:
            details.append("  • listings 설정 없음 (기본값 확인 필요)")
        
        # 4. WAS-04: 에러 페이지 설정
        details.append("\n[WAS-04] 에러 페이지 커스터마이징 확인")
        
        stdin, stdout, stderr = ssh.exec_command(f"grep -r 'error-page' {tomcat_home}/conf/ 2>/dev/null")
        error_page = stdout.read().decode().strip()
        
        if error_page:
            details.append("  ✓ 양호: 커스텀 에러 페이지 설정")
        else:
            result['vulnerabilities'].append("커스텀 에러 페이지 미설정")
            details.append("  ⚠ 주의: error-page 설정 권장")
        
        # 5. WAS-05: 실행 계정 권한 제한
        details.append("\n[WAS-05] Tomcat 실행 사용자 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "ps aux | grep tomcat | grep -v grep | head -1 | awk '{print $1}'"
        )
        tomcat_user = stdout.read().decode().strip()
        
        if tomcat_user == 'root':
            result['vulnerabilities'].append("Tomcat이 root 권한으로 실행")
            details.append(f"  ✗ 취약: root 권한 실행")
            result['status'] = 'VULNERABLE'
        elif tomcat_user:
            details.append(f"  ✓ 양호: {tomcat_user} 권한으로 실행")
        
        # 6. WAS-06: 파일 및 디렉터리 권한
        details.append("\n[WAS-06] Tomcat 파일 권한 확인")
        
        stdin, stdout, stderr = ssh.exec_command(f"ls -la {tomcat_home}/conf/server.xml | awk '{{print $1, $3, $4}}'")
        server_xml_perm = stdout.read().decode().strip()
        
        if server_xml_perm:
            details.append(f"  server.xml 권한: {server_xml_perm}")
            
            # 다른 사용자 읽기 권한 확인
            if server_xml_perm.startswith('-rw-r--r--'):
                result['vulnerabilities'].append("server.xml 타인 읽기 권한")
                details.append("  ⚠ 주의: 타인 읽기 권한 있음 (600 권장)")
        
        # 7. WAS-07: 불필요한 HTTP 메소드 제거
        details.append("\n[WAS-07] HTTP 메소드 제한 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            f"grep -r 'http-method' {tomcat_home}/conf/ {webapps_dir}/*/WEB-INF/web.xml 2>/dev/null"
        )
        http_method = stdout.read().decode().strip()
        
        if http_method:
            details.append("  ✓ HTTP 메소드 제한 설정됨")
        else:
            result['vulnerabilities'].append("HTTP 메소드 제한 없음")
            details.append("  ⚠ TRACE, PUT, DELETE 등 제한 권장")
        
        # 8. WAS-08: 웹 서버 연동 (AJP 포트)
        details.append("\n[WAS-08] AJP 커넥터 보안 확인")
        
        stdin, stdout, stderr = ssh.exec_command(f"grep -A 3 'AJP' {tomcat_home}/conf/server.xml")
        ajp_config = stdout.read().decode().strip()
        
        if ajp_config and not ajp_config.startswith('<!--'):
            details.append("  AJP 커넥터 활성화됨")
            
            # secretRequired 확인
            if 'secretRequired="true"' in ajp_config or 'secret=' in ajp_config:
                details.append("  ✓ AJP secret 설정됨")
            else:
                result['vulnerabilities'].append("AJP secret 미설정 (Ghostcat 취약점)")
                details.append("  ✗ 취약: AJP secret 없음")
                result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ AJP 커넥터 비활성화")
        
        # 9. WAS-09: 로그 설정
        details.append("\n[WAS-09] 로깅 설정 확인")
        
        logging_properties = f"{tomcat_home}/conf/logging.properties"
        stdin, stdout, stderr = ssh.exec_command(f"cat {logging_properties} 2>/dev/null | grep -v '^#' | grep '.level'")
        logging_config = stdout.read().decode().strip()
        
        if logging_config:
            details.append("  ✓ 양호: 로깅 설정 존재")
        else:
            details.append("  • 로깅 설정 확인 필요")
        
        # 10. WAS-10: 버전 정보 숨김
        details.append("\n[WAS-10] 서버 버전 정보 노출 차단")
        
        stdin, stdout, stderr = ssh.exec_command(f"grep -r 'server.info' {tomcat_home}/lib/*.jar 2>/dev/null")
        server_info = stdout.read().decode().strip()
        
        # ServerInfo.properties 수정 여부 확인 (복잡함)
        details.append("  • 버전 정보 숨김은 수동 확인 필요")
        details.append("    (ServerInfo.properties 파일 수정)")
        
        # Tomcat 버전 확인
        stdin, stdout, stderr = ssh.exec_command(f"{tomcat_home}/bin/version.sh 2>/dev/null | grep 'Server version'")
        tomcat_version = stdout.read().decode().strip()
        
        if tomcat_version:
            details.append(f"  현재 버전: {tomcat_version}")
            
            # 오래된 버전 확인
            import re
            version_match = re.search(r'(\d+\.\d+\.\d+)', tomcat_version)
            if version_match:
                version = version_match.group(1)
                major_version = int(version.split('.')[0])
                
                if major_version < 8:
                    result['vulnerabilities'].append(f"오래된 Tomcat 버전: {version}")
                    details.append(f"  ⚠ Tomcat {major_version} - 업데이트 권장")
        
        # 11. 추가: SSL/TLS 설정
        details.append("\n[WAS-추가] SSL/TLS 커넥터 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            f"grep -A 10 'Connector.*443' {tomcat_home}/conf/server.xml | grep -i ssl"
        )
        ssl_config = stdout.read().decode().strip()
        
        if ssl_config:
            details.append("  SSL/TLS 커넥터 설정됨")
            
            # 프로토콜 확인
            if 'sslProtocol' in ssl_config or 'protocols' in ssl_config:
                details.append("  ✓ SSL 프로토콜 설정됨")
        else:
            details.append("  • HTTPS 커넥터 없음")
        
        ssh.close()
        
    except paramiko.AuthenticationException:
        details.append("  [ERROR] SSH 인증 실패")
        result['status'] = 'ERROR'
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result