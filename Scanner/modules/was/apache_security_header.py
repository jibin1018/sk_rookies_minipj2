"""
KISA WAS 보안 가이드 - Apache 보안 헤더 설정
WS-04: HSTS, CSP 등 헤더
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Apache 보안 헤더 점검',
        'category': 'KISA WAS 보안 - 헤더 관리',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'Header always set Strict-Transport-Security "max-age=63072000"',
        'details': ''
    }
    details = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, ssh_port, ssh_user, ssh_pass, key_filename=ssh_key_file)
        
        # 헤더 설정 확인 (curl 시뮬)
        cmd = "curl -I https://localhost 2>/dev/null | grep -i 'strict-transport-security\|x-frame-options\|content-security-policy'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        headers = stdout.read().decode('utf-8', errors='ignore').strip()
        if not headers:
            result['status'] = 'VULNERABLE'
            details.append("⚠️ 보안 헤더 미설정")
        details.append(f"헤더: {headers}")
        
        ssh.close()
    except Exception as e:
        result['status'] = 'ERROR'
        details.append(f"오류: {str(e)}")
    
    result['details'] = '\n'.join(details)
    return result
