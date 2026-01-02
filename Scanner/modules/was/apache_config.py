import paramiko
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def check_apache_security(host, port, username, password):
    """
    Apache HTTP Server 보안 설정 점검 (KISA WAS 보안 가이드 기반)
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
        
        # 1. Apache 프로세스 확인
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep apache2 || ps aux | grep httpd")
        process_info = stdout.read().decode()
        
        if 'apache2' in process_info or 'httpd' in process_info:
            details.append("✓ Apache 서버 실행 중")
            
            # 2. Apache 설정 파일 확인
            stdin, stdout, stderr = ssh.exec_command("cat /etc/apache2/apache2.conf 2>/dev/null || cat /etc/httpd/conf/httpd.conf 2>/dev/null")
            config_content = stdout.read().decode()
            
            # 3. 서버 토큰 숨기기 확인
            if 'ServerTokens Prod' not in config_content and 'ServerSignature Off' not in config_content:
                details.append("✗ [취약] 서버 정보 노출")
                result['vulnerabilities'].append({
                    'category': '정보노출',
                    'item': 'Apache 버전 정보 숨김',
                    'severity': 'MEDIUM',
                    'description': 'ServerTokens와 ServerSignature가 안전하게 설정되지 않음',
                    'recommendation': 'ServerTokens Prod와 ServerSignature Off 설정'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 서버 정보 숨김 설정")
            
            # 4. 디렉토리 리스팅 방지
            if 'Options Indexes' in config_content:
                details.append("✗ [취약] 디렉토리 리스팅 활성화")
                result['vulnerabilities'].append({
                    'category': '정보노출',
                    'item': '디렉토리 리스팅',
                    'severity': 'MEDIUM',
                    'description': 'Options에 Indexes가 포함되어 디렉토리 목록 노출',
                    'recommendation': 'Options -Indexes로 변경'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 디렉토리 리스팅 비활성화")
            
            # 5. SSL/TLS 설정 확인
            if 'SSLProtocol' in config_content:
                if 'TLSv1 ' in config_content or 'SSLv3' in config_content:
                    details.append("✗ [취약] 취약한 SSL/TLS 프로토콜 사용")
                    result['vulnerabilities'].append({
                        'category': '암호화통신',
                        'item': 'SSL/TLS 프로토콜 버전',
                        'severity': 'HIGH',
                        'description': '취약한 SSLv3/TLSv1.0 프로토콜 사용',
                        'recommendation': 'SSLProtocol -all +TLSv1.2 +TLSv1.3 설정'
                    })
                    result['status'] = 'VULNERABLE'
                else:
                    details.append("✓ 안전한 SSL/TLS 프로토콜 설정")
            else:
                details.append("⚠ SSL/TLS 설정 확인 필요")
            
            # 6. 불필요한 모듈 확인
            dangerous_modules = ['mod_status', 'mod_info', 'mod_userdir']
            loaded_modules = []
            
            stdin, stdout, stderr = ssh.exec_command("apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null")
            modules_info = stdout.read().decode()
            
            for module in dangerous_modules:
                if module in modules_info:
                    loaded_modules.append(module)
            
            if loaded_modules:
                details.append(f"✗ [취약] 위험한 모듈 로드됨: {', '.join(loaded_modules)}")
                result['vulnerabilities'].append({
                    'category': '보안설정',
                    'item': '불필요한 모듈',
                    'severity': 'MEDIUM',
                    'description': f'위험한 모듈이 로드됨: {', '.join(loaded_modules)}',
                    'recommendation': 'mod_status, mod_info 등 불필요한 모듈 비활성화'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 위험한 모듈 비활성화")
            
            # 7. 실행 계정 확인
            if 'User root' in config_content or 'Group root' in config_content:
                details.append("✗ [취약] root 계정으로 실행")
                result['vulnerabilities'].append({
                    'category': '권한관리',
                    'item': 'Apache 실행 계정',
                    'severity': 'HIGH',
                    'description': 'root 계정으로 Apache 실행',
                    'recommendation': 'User www-data 등 일반 계정으로 변경'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 일반 계정으로 실행")
            
            # 8. 보안 헤더 확인
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']
            missing_headers = []
            
            for header in security_headers:
                if f'Header set {header}' not in config_content:
                    missing_headers.append(header)
            
            if missing_headers:
                details.append(f"✗ [취약] 보안 헤더 미설정: {', '.join(missing_headers)}")
                result['vulnerabilities'].append({
                    'category': '보안설정',
                    'item': 'HTTP 보안 헤더',
                    'severity': 'MEDIUM',
                    'description': f'보안 헤더가 누락됨: {', '.join(missing_headers)}',
                    'recommendation': '보안 헤더 추가 권장'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 보안 헤더 설정됨")
            
            # 9. 로그 설정 확인
            if 'CustomLog' in config_content or 'ErrorLog' in config_content:
                details.append("✓ 로그 설정 활성화")
            else:
                details.append("⚠ 로그 설정 확인 필요")
            
            # 10. Apache 버전 확인
            stdin, stdout, stderr = ssh.exec_command("apache2 -v 2>/dev/null || httpd -v 2>/dev/null")
            version_info = stdout.read().decode()
            
            if version_info:
                details.append(f"✓ 설치 버전: {version_info.strip().split()[2] if len(version_info.strip().split()) > 2 else version_info.strip()}")
            else:
                details.append("⚠ 버전 정보 확인 불가")
            
        else:
            details.append("✗ Apache 서버가 실행되고 있지 않음")
        
        ssh.close()
        
    except paramiko.AuthenticationException:
        details.append("✗ [ERROR] SSH 인증 실패")
        result['status'] = 'ERROR'
    except Exception as e:
        details.append(f"✗ [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = details
    return result
