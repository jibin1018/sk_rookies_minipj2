"""
KISA WAS 보안 가이드 - Apache 디렉토리 리스팅 차단 (AP-05, NG-05)
WS-02: Options -Indexes 설정
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ssh_utils import safe_ssh_connect, create_error_result
def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Apache 디렉토리 리스팅 차단 점검',
        'category': 'KISA WAS 보안 - 보안 설정',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'Options -Indexes 추가',
        'details': ''
    }
    details = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, ssh_port, ssh_user, ssh_pass, key_filename=ssh_key_file)
        
        # httpd.conf Options 확인
        cmd = "grep -i 'Options' /etc/httpd/conf/httpd.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -i indexes"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        options = stdout.read().decode('utf-8', errors='ignore').strip()
        if 'Indexes' in options and '+Indexes' not in options:
            details.append("⚠️ Indexes 활성화됨")
            result['status'] = 'VULNERABLE'
        else:
            details.append("✓ Indexes 차단 또는 미설정")
        
        details.append(f"Options 설정: {options}")
        ssh.close()
    except Exception as e:
        result['status'] = 'ERROR'
        details.append(f"오류: {str(e)}")
    
    result['details'] = '\n'.join(details)
    return result
