"""
KISA WAS 보안 가이드 - Apache 로그 설정 (로깅 활성화)
WS-05: 접근/오류 로그, 보존 기간
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Apache 로그 설정 점검',
        'category': 'KISA WAS 보안 - 로깅',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'CustomLog 활성화, logrotate 90일 보존',
        'details': ''
    }
    details = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, ssh_port, ssh_user, ssh_pass, key_filename=ssh_key_file)
        
        # 로그 설정 확인
        cmd = "grep -i 'CustomLog\\|ErrorLog' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        log_config = stdout.read().decode('utf-8', errors='ignore').strip()
        if not log_config:
            result['status'] = 'VULNERABLE'
            details.append("⚠️ 로그 설정 미확인")
        details.append(f"로그 설정: {log_config}")
        
        # 로그 파일 존재/권한
        cmd = "ls -la /var/log/httpd/ /var/log/apache2/ 2>/dev/null"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        log_files = stdout.read().decode('utf-8', errors='ignore').strip()
        details.append(f"로그 파일: {log_files[:200]}...")
        
        ssh.close()
    except Exception as e:
        result['status'] = 'ERROR'
        details.append(f"오류: {str(e)}")
    
    result['details'] = '\n'.join(details)
    return result
