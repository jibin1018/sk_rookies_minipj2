"""
KISA 웹 서버 보안 가이드 - Apache 보안 설정
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ssh_utils import safe_ssh_connect, create_error_result
def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'W-01~W-10: Apache 웹서버 보안 설정',
        'category': 'KISA 웹서버 보안',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'Apache 보안 설정 강화: 버전 숨김, 디렉터리 리스팅 차단, 불필요한 모듈 제거',
        'details': ''
    }
    
    details = []
    
    # SSH 연결 (안전)
    ssh, error = safe_ssh_connect(ssh_host, ssh_user, ssh_pass, ssh_port, ssh_key_file)

    if error:
        # SSH 연결 실패 시 ERROR 결과 반환
        module_name = result.get('name', 'Unknown Module')
        return create_error_result(module_name, error, 'ERROR')

    try:
        
        # Apache 설치 확인
        stdin, stdout, stderr = ssh.exec_command("which apache2 httpd 2>/dev/null | head -1")
        apache_path = stdout.read().decode().strip()
        
        if not apache_path:
            details.append("  [INFO] Apache 웹서버가 설치되지 않음")
            result['status'] = 'N/A'
            result['details'] = '\n'.join(details)
            ssh.close()
            return result
        
        details.append(f"Apache 경로: {apache_path}")
        
        # Apache 설정 파일 위치 찾기
        stdin, stdout, stderr = ssh.exec_command(
            "find /etc -name 'apache2.conf' -o -name 'httpd.conf' 2>/dev/null | head -1"
        )
        config_file = stdout.read().decode().strip()
        
        if not config_file:
            details.append("  [ERROR] Apache 설정 파일을 찾을 수 없음")
            result['status'] = 'ERROR'
            result['details'] = '\n'.join(details)
            ssh.close()
            return result
        
        details.append(f"설정 파일: {config_file}")
        
        # 1. W-01: 디렉터리 리스팅 차단
        details.append("\n[W-01] 디렉터리 리스팅 차단 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            f"grep -r 'Options.*Indexes' {config_file} /etc/apache2/sites-enabled/ /etc/apache2/conf-enabled/ 2>/dev/null"
        )
        indexes_config = stdout.read().decode().strip()
        
        if indexes_config and not indexes_config.startswith('#'):
            # Indexes가 설정되어 있는지 확인
            if 'Indexes' in indexes_config and '-Indexes' not in indexes_config:
                result['vulnerabilities'].append("디렉터리 리스팅 활성화됨")
                details.append(f"  ✗ 취약: Indexes 옵션 발견")
                for line in indexes_config.split('\n')[:3]:
                    details.append(f"    {line}")
                result['status'] = 'VULNERABLE'
            else:
                details.append("  ✓ 양호: -Indexes 설정됨")
        else:
            details.append("  ✓ 양호: Options Indexes 없음")
        
        # 2. W-02: 웹 프로세스 권한 제한
        details.append("\n[W-02] Apache 실행 사용자 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "ps aux | grep -E 'apache2|httpd' | grep -v grep | head -1 | awk '{print $1}'"
        )
        apache_user = stdout.read().decode().strip()
        
        if apache_user in ['root']:
            result['vulnerabilities'].append("Apache가 root 권한으로 실행 중")
            details.append(f"  ✗ 취약: {apache_user} 권한으로 실행")
            result['status'] = 'VULNERABLE'
        elif apache_user:
            details.append(f"  ✓ 양호: {apache_user} 권한으로 실행")
            
            # User, Group 지시자 확인
            stdin, stdout, stderr = ssh.exec_command(f"grep -E '^(User|Group)' {config_file}")
            user_config = stdout.read().decode().strip()
            if user_config:
                details.append(f"    설정: {user_config}")
        else:
            details.append("  • Apache 프로세스 미실행")
        
        # 3. W-03: 웹서버 불필요한 파일 제거
        details.append("\n[W-03] 기본 페이지 및 샘플 파일 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "find /var/www -type f \\( -name 'index.html' -o -name 'test.php' -o -name 'info.php' \\) 2>/dev/null | head -10"
        )
        default_files = stdout.read().decode().strip()
        
        if default_files:
            files_list = default_files.split('\n')
            details.append(f"  ⚠ 주의: {len(files_list)}개 기본/테스트 파일 발견")
            for f in files_list[:3]:
                details.append(f"    - {f}")
        else:
            details.append("  ✓ 양호: 불필요한 파일 없음")
        
        # 4. W-04: 웹서버 링크 사용 금지
        details.append("\n[W-04] 심볼릭 링크 차단 확인")
        
        stdin, stdout, stderr = ssh.exec_command(f"grep -i 'FollowSymLinks' {config_file}")
        symlinks = stdout.read().decode().strip()
        
        if 'FollowSymLinks' in symlinks and not symlinks.startswith('#'):
            if '+FollowSymLinks' in symlinks or 'FollowSymLinks' in symlinks:
                result['vulnerabilities'].append("심볼릭 링크 허용됨")
                details.append(f"  ✗ 취약: FollowSymLinks 활성화")
                result['status'] = 'VULNERABLE'
            elif '-FollowSymLinks' in symlinks:
                details.append("  ✓ 양호: -FollowSymLinks 설정")
        else:
            details.append("  ✓ 양호: FollowSymLinks 설정 없음")
        
        # 5. W-05: 파일 업로드 및 다운로드 제한
        details.append("\n[W-05] 파일 업로드 크기 제한 확인")
        
        stdin, stdout, stderr = ssh.exec_command(f"grep -i 'LimitRequestBody' {config_file}")
        limit_body = stdout.read().decode().strip()
        
        if limit_body and not limit_body.startswith('#'):
            details.append(f"  ✓ 양호: {limit_body}")
        else:
            result['vulnerabilities'].append("파일 업로드 크기 제한 없음")
            details.append("  ⚠ 주의: LimitRequestBody 설정 없음")
        
        # 6. W-06: 상위 디렉터리 접근 금지
        details.append("\n[W-06] 상위 디렉터리 접근 차단 확인")
        
        stdin, stdout, stderr = ssh.exec_command(f"grep -i 'AllowOverride' {config_file}")
        allow_override = stdout.read().decode().strip()
        
        if 'AllowOverride All' in allow_override and not allow_override.startswith('#'):
            result['vulnerabilities'].append("AllowOverride All 설정됨 (보안 위험)")
            details.append(f"  ✗ 취약: AllowOverride All")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ 양호: AllowOverride 제한됨")
        
        # 7. W-07: 불필요한 HTTP 메소드 제한
        details.append("\n[W-07] HTTP 메소드 제한 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            f"grep -r 'LimitExcept' {config_file} /etc/apache2/sites-enabled/ 2>/dev/null"
        )
        limit_except = stdout.read().decode().strip()
        
        if limit_except:
            details.append(f"  ✓ 양호: HTTP 메소드 제한 설정됨")
            details.append(f"    {limit_except[:100]}...")
        else:
            result['vulnerabilities'].append("HTTP 메소드 제한 없음 (TRACE, DELETE 등 허용 가능)")
            details.append("  ⚠ 주의: LimitExcept 설정 없음")
        
        # TRACE 메소드 비활성화 확인
        stdin, stdout, stderr = ssh.exec_command(f"grep -i 'TraceEnable' {config_file}")
        trace_enable = stdout.read().decode().strip()
        
        if 'TraceEnable Off' in trace_enable:
            details.append("  ✓ TraceEnable Off 설정됨")
        else:
            result['vulnerabilities'].append("TRACE 메소드 활성화 가능")
            details.append("  ⚠ TraceEnable Off 미설정")
        
        # 8. W-08: 웹서버 에러 페이지 설정
        details.append("\n[W-08] 에러 페이지 설정 확인")
        
        stdin, stdout, stderr = ssh.exec_command(f"grep -i 'ErrorDocument' {config_file}")
        error_doc = stdout.read().decode().strip()
        
        if error_doc and not error_doc.startswith('#'):
            details.append(f"  ✓ 양호: 커스텀 에러 페이지 설정")
            for line in error_doc.split('\n')[:3]:
                details.append(f"    {line}")
        else:
            details.append("  ⚠ 주의: 커스텀 에러 페이지 미설정")
        
        # 9. W-09: 웹서버 보안 패치 (버전 확인)
        details.append("\n[W-09] Apache 버전 확인")
        
        stdin, stdout, stderr = ssh.exec_command("apache2 -v 2>/dev/null || httpd -v 2>/dev/null")
        apache_version = stdout.read().decode().strip()
        
        if apache_version:
            version_line = apache_version.split('\n')[0]
            details.append(f"  현재 버전: {version_line}")
            
            # 버전 번호 추출
            import re
            version_match = re.search(r'Apache/(\d+\.\d+\.\d+)', version_line)
            if version_match:
                version = version_match.group(1)
                
                # 알려진 취약 버전
                if version < '2.4.49':
                    details.append("  ⚠ 주의: 보안 패치 확인 필요")
                else:
                    details.append("  ✓ 최신 버전")
        else:
            details.append("  • 버전 확인 불가")
        
        # 10. W-10: 웹서버 정보 노출 차단
        details.append("\n[W-10] 서버 정보 노출 차단 확인")
        
        # ServerTokens
        stdin, stdout, stderr = ssh.exec_command(f"grep -i 'ServerTokens' {config_file}")
        server_tokens = stdout.read().decode().strip()
        
        if 'ServerTokens Prod' in server_tokens:
            details.append(f"  ✓ 양호: ServerTokens Prod")
        elif 'ServerTokens' in server_tokens:
            details.append(f"  ⚠ 주의: {server_tokens}")
            result['vulnerabilities'].append("서버 정보 노출 가능")
            result['status'] = 'VULNERABLE'
        else:
            result['vulnerabilities'].append("ServerTokens 미설정 (기본값: Full)")
            details.append(f"  ✗ 취약: ServerTokens 설정 없음")
            result['status'] = 'VULNERABLE'
        
        # ServerSignature
        stdin, stdout, stderr = ssh.exec_command(f"grep -i 'ServerSignature' {config_file}")
        server_sig = stdout.read().decode().strip()
        
        if 'ServerSignature Off' in server_sig:
            details.append(f"  ✓ 양호: ServerSignature Off")
        else:
            result['vulnerabilities'].append("ServerSignature 노출")
            details.append(f"  ✗ 취약: ServerSignature Off 미설정")
            result['status'] = 'VULNERABLE'
        
        # 11. 추가: 불필요한 모듈 확인
        details.append("\n[W-추가] 활성화된 모듈 확인")
        
        stdin, stdout, stderr = ssh.exec_command("apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null")
        loaded_modules = stdout.read().decode().strip()
        
        if loaded_modules:
            dangerous_modules = ['dav_module', 'dav_fs_module', 'dav_lock_module', 'proxy_module']
            
            for mod in dangerous_modules:
                if mod in loaded_modules:
                    details.append(f"  ⚠ 주의: {mod} 활성화됨 (필요 시에만 사용)")
        
        ssh.close()
        
    except paramiko.AuthenticationException:
        details.append("  [ERROR] SSH 인증 실패")
        result['status'] = 'ERROR'
    except paramiko.SSHException as e:
        details.append(f"  [ERROR] SSH 연결 오류: {str(e)}")
        result['status'] = 'ERROR'
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result