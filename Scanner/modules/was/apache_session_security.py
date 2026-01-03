"""
KISA WAS 보안 가이드 - Apache 세션 보안 (세션 관련)
WS-10: Session Cookie HttpOnly, Secure 플래그
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Apache 세션 보안 점검',
        'category': 'KISA WAS 보안 - 세션 관리',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure',
        'details': ''
    }
    details = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, ssh_port, ssh_user, ssh_pass, key_filename=ssh_key_file)
        
        # 세션 쿠키 헤더 설정 확인
        cmd = "grep -i 'Header.*Set-Cookie.*HttpOnly' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        session_header = stdout.read().decode('utf-8', errors='ignore').strip()
        if not session_header:
            result['status'] = 'VULNERABLE'
            details.append("⚠️ HttpOnly/Secure 플래그 미설정")
        details.append(f"세션 헤더: {session_header}")
        
        # PHP 세션 확인 (일반적)
        stdin, stdout, stderr = ssh.exec_command("grep session.cookie_ /etc/php.ini 2>/dev/null")
        php_session = stdout.read().decode('utf-8', errors='ignore').strip()
        details.append(f"PHP 세션: {php_session}")
        
        ssh.close()
    except Exception as e:
        result['status'] = 'ERROR'
        details.append(f"오류: {str(e)}")
    
    result['details'] = '\n'.join(details)
    return result
