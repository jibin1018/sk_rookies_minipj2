"""
KISA WAS 보안 가이드 - Apache 버전 정보 및 패치 (AP-01)
WS-06: ServerTokens Prod, 최신 버전
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ssh_utils import safe_ssh_connect, create_error_result
def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Apache 버전 및 패치 점검',
        'category': 'KISA WAS 보안 - 패치 관리',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'ServerTokens Prod, yum update httpd',
        'details': ''
    }
    details = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, ssh_port, ssh_user, ssh_pass, key_filename=ssh_key_file)
        
        # Apache 버전 확인
        stdin, stdout, stderr = ssh.exec_command("httpd -v 2>/dev/null || apache2 -v || echo 'Apache 미설치'")
        version = stdout.read().decode('utf-8', errors='ignore').strip()
        details.append(f"버전: {version}")
        
        # ServerTokens 설정 (Prod로 숨김)
        cmd = "grep -i 'ServerTokens' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        tokens = stdout.read().decode('utf-8', errors='ignore').strip()
        if 'Prod' not in tokens:
            result['status'] = 'VULNERABLE'
            details.append("⚠️ ServerTokens Prod 미설정 (버전 노출)")
        
        details.append(f"ServerTokens: {tokens}")
        ssh.close()
    except Exception as e:
        result['status'] = 'ERROR'
        details.append(f"오류: {str(e)}")
    
    result['details'] = '\n'.join(details)
    return result
