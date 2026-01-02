import paramiko
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def check_iis_security(host, port, username, password):
    """
    IIS (Internet Information Services) 보안 설정 점검 (KISA WAS 보안 가이드 기반)
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
        
        # 1. IIS 프로세스 확인 (Windows 환경)
        stdin, stdout, stderr = ssh.exec_command("tasklist | findstr w3wp")
        process_info = stdout.read().decode()
        
        if 'w3wp.exe' in process_info:
            details.append("✓ IIS 서버 실행 중")
            
            # 2. IIS 버전 확인
            stdin, stdout, stderr = ssh.exec_command("reg query \"HKLM\\SOFTWARE\\Microsoft\\InetStp\" /v VersionString")
            version_info = stdout.read().decode()
            
            if version_info:
                details.append(f"✓ 설치 버전: {version_info.strip().split()[-1] if version_info.strip().split() else 'Unknown'}")
            
            # 3. 디렉토리 브라우징 확인
            stdin, stdout, stderr = ssh.exec_command("%windir%\\system32\\inetsrv\\appcmd.exe list config -section:directoryBrowse")
            dir_browse = stdout.read().decode()
            
            if 'enabled=\"true\"' in dir_browse:
                details.append("✗ [취약] 디렉토리 브라우징 활성화")
                result['vulnerabilities'].append({
                    'category': '정보노출',
                    'item': '디렉토리 브라우징',
                    'severity': 'MEDIUM',
                    'description': '디렉토리 목록이 노출되도록 설정됨',
                    'recommendation': 'IIS 관리자에서 Directory Browsing 비활성화'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 디렉토리 브라우징 비활성화")
            
            # 4. 상세 오류 메시지 확인
            stdin, stdout, stderr = ssh.exec_command("%windir%\\system32\\inetsrv\\appcmd.exe list config -section:httpErrors")
            http_errors = stdout.read().decode()
            
            if 'errorMode=\"Detailed\"' in http_errors:
                details.append("✗ [취약] 상세 오류 메시지 노출")
                result['vulnerabilities'].append({
                    'category': '정보노출',
                    'item': 'HTTP 오류 메시지',
                    'severity': 'MEDIUM',
                    'description': '상세한 오류 메시지가 노출됨',
                    'recommendation': 'errorMode를 DetailedLocalOnly 또는 Custom으로 변경'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 상세 오류 메시지 숨김 설정")
            
            # 5. 보안 헤더 확인
            stdin, stdout, stderr = ssh.exec_command("%windir%\\system32\\inetsrv\\appcmd.exe list config -section:httpProtocol")
            headers_info = stdout.read().decode()
            
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']
            missing_headers = []
            
            for header in security_headers:
                if header not in headers_info:
                    missing_headers.append(header)
            
            if missing_headers:
                details.append(f"✗ [취약] 보안 헤더 미설정: {', '.join(missing_headers)}")
                result['vulnerabilities'].append({
                    'category': '보안설정',
                    'item': 'HTTP 보안 헤더',
                    'severity': 'MEDIUM',
                    'description': f'보안 헤더가 누락됨: {', '.join(missing_headers)}',
                    'recommendation': 'IIS에서 보안 헤더 추가'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 보안 헤더 설정됨")
            
            # 6. SSL/TLS 설정 확인
            stdin, stdout, stderr = ssh.exec_command("reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server\" /v Enabled")
            tls10_status = stdout.read().decode()
            
            if 'Enabled    REG_DWORD    0x1' in tls10_status:
                details.append("✗ [취약] 취약한 TLS 1.0 프로토콜 활성화")
                result['vulnerabilities'].append({
                    'category': '암호화통신',
                    'item': 'SSL/TLS 프로토콜 버전',
                    'severity': 'HIGH',
                    'description': '취약한 TLS 1.0 프로토콜이 활성화됨',
                    'recommendation': 'TLS 1.0/1.1 비활성화 및 TLS 1.2/1.3만 사용'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 안전한 TLS 프로토콜 설정")
            
            # 7. Request Filtering 확인
            stdin, stdout, stderr = ssh.exec_command("%windir%\\system32\\inetsrv\\appcmd.exe list config -section:requestFiltering")
            req_filter = stdout.read().decode()
            
            if 'allowDoubleEscaping=\"true\"' in req_filter:
                details.append("✗ [취약] Double Escaping 허용")
                result['vulnerabilities'].append({
                    'category': '보안설정',
                    'item': 'Request Filtering',
                    'severity': 'MEDIUM',
                    'description': 'Double Escaping이 허용됨',
                    'recommendation': 'allowDoubleEscaping을 false로 설정'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ Request Filtering 안전하게 설정")
            
            # 8. 응용 풀 ID 확인
            stdin, stdout, stderr = ssh.exec_command("%windir%\\system32\\inetsrv\\appcmd.exe list apppool /text:processModel.identityType")
            pool_identity = stdout.read().decode()
            
            if 'LocalSystem' in pool_identity:
                details.append("✗ [취약] LocalSystem 계정으로 실행")
                result['vulnerabilities'].append({
                    'category': '권한관리',
                    'item': '응용 풀 ID',
                    'severity': 'HIGH',
                    'description': 'LocalSystem 계정으로 응용 풀 실행',
                    'recommendation': 'ApplicationPoolIdentity 또는 제한된 계정 사용'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 안전한 계정으로 실행")
            
            # 9. 로깅 설정 확인
            stdin, stdout, stderr = ssh.exec_command("%windir%\\system32\\inetsrv\\appcmd.exe list config -section:httpLogging")
            logging_info = stdout.read().decode()
            
            if 'dontLog=\"true\"' in logging_info:
                details.append("⚠ 로깅 비활성화")
            else:
                details.append("✓ 로깅 활성화")
            
        else:
            details.append("✗ IIS 서버가 실행되고 있지 않음")
        
        ssh.close()
        
    except paramiko.AuthenticationException:
        details.append("✗ [ERROR] SSH 인증 실패")
        result['status'] = 'ERROR'
    except Exception as e:
        details.append(f"✗ [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = details
    return result
