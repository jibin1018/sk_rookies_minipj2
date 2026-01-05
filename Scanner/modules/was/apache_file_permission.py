"""
KISA WAS 보안 가이드 - Apache 파일/디렉토리 권한 (SRV-084)
WS-07: conf/logs 755 이하, 소유자 apache
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Apache 파일 권한 점검',
        'category': 'KISA WAS 보안 - 파일 권한',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'chown -R apache:apache /etc/httpd/conf/, chmod 750',
        'details': ''
    }
    details = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, ssh_port, ssh_user, ssh_pass, key_filename=ssh_key_file)
        
        # conf 디렉토리 권한
        cmd = "ls -la /etc/httpd/conf/ /etc/apache2/ 2>/dev/null | head -10"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        perms = stdout.read().decode('utf-8', errors='ignore').strip()
        if '777' in perms or 'rwxrwxrwx' in perms:
            result['status'] = 'VULNERABLE'
            details.append("⚠️ 과도한 권한 (777 등)")
        details.append("conf 권한:\n" + perms)
        
        # logs 권한
        cmd = "ls -la /var/log/httpd/ /var/log/apache2/ 2>/dev/null | head -5"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        log_perms = stdout.read().decode('utf-8', errors='ignore').strip()
        details.append("logs 권한:\n" + log_perms)
        
        ssh.close()
    except Exception as e:
        result['status'] = 'ERROR'
        details.append(f"오류: {str(e)}")
    
    result['details'] = '\n'.join(details)
    return result
