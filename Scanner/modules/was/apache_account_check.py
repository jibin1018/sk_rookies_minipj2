"""
KISA WAS 보안 가이드 - Apache 계정 및 권한 점검 (AP-06)
WS-01: root 실행 방지, 최소 권한 사용자
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Apache 계정 및 권한 점검',
        'category': 'KISA WAS 보안 - 접근 관리',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': 'User apache, Group apache 설정, root 실행 금지',
        'details': ''
    }
    details = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, ssh_port, ssh_user, ssh_pass, key_filename=ssh_key_file)
        
        # 실행 프로세스 사용자 확인
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep httpd | grep -v grep | awk '{print $1}' | sort -u")
        users = stdout.read().decode('utf-8', errors='ignore').strip()
        if 'root' in users:
            result['status'] = 'VULNERABLE'
            result['vulnerabilities'].append('root 사용자로 Apache 실행')
            details.append("⚠️ root 권한으로 실행 중 (ps aux 확인)")
        else:
            details.append("✓ 비 root 사용자 (apache/www-data) 실행")
        
        # httpd.conf User/Group 설정
        cmd = "grep -E '^User|^Group' /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null || echo '설정 파일 없음'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        config = stdout.read().decode('utf-8', errors='ignore').strip()
        details.append(f"설정: {config}")
        
        ssh.close()
    except Exception as e:
        result['status'] = 'ERROR'
        details.append(f"오류: {str(e)}")
    
    result['details'] = '\n'.join(details)
    return result
