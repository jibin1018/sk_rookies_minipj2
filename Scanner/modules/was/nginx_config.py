import paramiko
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def check_nginx_security(host, port, username, password):
    """
    Nginx 보안 설정 점검 (KISA WAS 보안 가이드 기반)
    """
    result = {
        'host': host,
        'port': port,
        'scan_time': datetime.now().isoformat(),
        'vulnerabilities': [],
        'status': 'SAFE'
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password, timeout=10)
        
        # 1. Nginx 프로세스 확인
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep nginx")
        process_info = stdout.read().decode()
        
        if 'nginx' in process_info and 'grep' not in process_info:
            details.append("✓ Nginx 서버 실행 중")
            
            # 2. Nginx 설정 파일 확인
            stdin, stdout, stderr = ssh.exec_command("cat /etc/nginx/nginx.conf 2>/dev/null")
            config_content = stdout.read().decode()
            
            # 3. 서버 버전 숨기기 확인
            if 'server_tokens off' not in config_content:
                details.append("✗ [취약] 서버 버전 정보 노출")
                result['vulnerabilities'].append({
                    'category': '정보노출',
                    'item': 'Nginx 버전 정보 숨김',
                    'severity': 'MEDIUM',
                    'description': 'server_tokens가 off로 설정되지 않음',
                    'recommendation': 'nginx.conf에서 server_tokens off 설정 필요'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 서버 버전 정보 숨김 설정")
            
            # 4. SSL/TLS 설정 확인
            if 'ssl_protocols' in config_content:
                if 'TLSv1' in config_content and 'TLSv1.2' not in config_content:
                    details.append("✗ [취약] 취약한 SSL/TLS 프로토콜 사용")
                    result['vulnerabilities'].append({
                        'category': '암호화통신',
                        'item': 'SSL/TLS 프로토콜 버전',
                        'severity': 'HIGH',
                        'description': '취약한 TLSv1.0/1.1 프로토콜 사용',
                        'recommendation': 'ssl_protocols TLSv1.2 TLSv1.3만 사용하도록 설정'
                    })
                    result['status'] = 'VULNERABLE'
                else:
                    details.append("✓ 안전한 SSL/TLS 프로토콜 설정")
            else:
                details.append("⚠ SSL/TLS 설정 확인 필요")
            
            # 5. 보안 헤더 확인
            security_headers = [
                ('X-Frame-Options', 'add_header X-Frame-Options'),
                ('X-Content-Type-Options', 'add_header X-Content-Type-Options'),
                ('X-XSS-Protection', 'add_header X-XSS-Protection')
            ]
            
            missing_headers = []
            for header_name, header_directive in security_headers:
                if header_directive not in config_content:
                    missing_headers.append(header_name)
            
            if missing_headers:
                details.append(f"✗ [취약] 보안 헤더 미설정: {', '.join(missing_headers)}")
                result['vulnerabilities'].append({
                    'category': '보안설정',
                    'item': 'HTTP 보안 헤더',
                    'severity': 'MEDIUM',
                    'description': f'보안 헤더가 누락됨: {', '.join(missing_headers)}',
                    'recommendation': 'X-Frame-Options, X-Content-Type-Options, X-XSS-Protection 헤더 추가'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 보안 헤더 설정됨")
            
            # 6. 디렉토리 리스팅 방지
            if 'autoindex on' in config_content:
                details.append("✗ [취약] 디렉토리 리스팅 활성화")
                result['vulnerabilities'].append({
                    'category': '정보노출',
                    'item': '디렉토리 리스팅',
                    'severity': 'MEDIUM',
                    'description': 'autoindex on으로 설정되어 디렉토리 목록 노출',
                    'recommendation': 'autoindex off로 변경'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 디렉토리 리스팅 비활성화")
            
            # 7. worker 프로세스 실행 계정 확인
            if 'user root' in config_content or 'user nginx' not in config_content:
                details.append("✗ [취약] root 계정으로 실행")
                result['vulnerabilities'].append({
                    'category': '권한관리',
                    'item': 'Worker 프로세스 실행 계정',
                    'severity': 'HIGH',
                    'description': 'root 계정으로 worker 프로세스 실행',
                    'recommendation': 'user nginx; 등 일반 계정으로 변경'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 일반 계정으로 실행")
            
            # 8. 접근 로그 설정 확인
            if 'access_log' in config_content and 'access_log off' not in config_content:
                details.append("✓ 접근 로그 활성화")
            else:
                details.append("⚠ 접근 로그 설정 확인 필요")
            
            # 9. client_max_body_size 확인
            if 'client_max_body_size' not in config_content:
                details.append("⚠ 업로드 파일 크기 제한 미설정")
            else:
                details.append("✓ 업로드 파일 크기 제한 설정")
            
            # 10. Nginx 버전 확인
            stdin, stdout, stderr = ssh.exec_command("nginx -v 2>&1")
            version_info = stdout.read().decode()
            
            if version_info:
                details.append(f"✓ 설치 버전: {version_info.strip()}")
            else:
                details.append("⚠ 버전 정보 확인 불가")
            
        else:
            details.append("✗ Nginx 서버가 실행되고 있지 않음")
        
        ssh.close()
        
    except paramiko.AuthenticationException:
        details.append("✗ [ERROR] SSH 인증 실패")
        result['status'] = 'ERROR'
    except Exception as e:
        details.append(f"✗ [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = details
    return result
