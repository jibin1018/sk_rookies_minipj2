"""
KISA WAS 보안 가이드 - Apache DoS 방어 (SRV-023)
WS-09: mod_security, LimitRequestBody 설정
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Apache DoS 보호 점검',
        'category': 'KISA WAS 보안 - DoS 방어',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'LimitRequestBody 1048576, mod_security 활성화',
        'details': ''
    }
    details = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, ssh_port, ssh_user, ssh_pass, key_filename=ssh_key_file)
        
        # LimitRequestBody 확인
        cmd = "grep -i 'LimitRequestBody' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        limit = stdout.read().decode('utf-8', errors='ignore').strip()
        if not limit:
            result['status'] = 'VULNERABLE'
            details.append("⚠️ LimitRequestBody 미설정")
        details.append(f"LimitRequestBody: {limit}")
        
        # mod_security 확인
        stdin, stdout, stderr = ssh.exec_command("httpd -M 2>/dev/null | grep security")
        mod_sec = stdout.read().decode('utf-8', errors='ignore').strip()
        details.append(f"mod_security: {mod_sec}")
        
        ssh.close()
    except Exception as e:
        result['status'] = 'ERROR'
        details.append(f"오류: {str(e)}")
    
    result['details'] = '\n'.join(details)
    return result
