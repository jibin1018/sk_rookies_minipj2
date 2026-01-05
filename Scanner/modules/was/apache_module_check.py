"""
KISA WAS 보안 가이드 - Apache 불필요 모듈 비활성화 (AP-04)
WS-08: mod_status, mod_info, mod_userdir off
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ssh_utils import safe_ssh_connect, create_error_result
def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Apache 모듈 점검',
        'category': 'KISA WAS 보안 - 모듈 관리',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'LoadModule status_module off',
        'details': ''
    }
    details = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, ssh_port, ssh_user, ssh_pass, key_filename=ssh_key_file)
        
        # 로드된 모듈 확인
        stdin, stdout, stderr = ssh.exec_command("httpd -M 2>/dev/null | grep -E 'status_module|info_module|userdir_module'")
        loaded = stdout.read().decode('utf-8', errors='ignore').strip()
        if loaded:
            result['status'] = 'VULNERABLE'
            details.append("⚠️ 위험 모듈 로드됨: " + loaded)
        else:
            details.append("✓ 위험 모듈 미로드")
        
        details.append("로드 모듈 일부: " + loaded)
        ssh.close()
    except Exception as e:
        result['status'] = 'ERROR'
        details.append(f"오류: {str(e)}")
    
    result['details'] = '\n'.join(details)
    return result
