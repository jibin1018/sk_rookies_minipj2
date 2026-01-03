"""
KISA WAS 보안 가이드 - Apache SSL/TLS 설정 (AP-SSL 관련)
WS-03: TLS 1.2+ , 약한 cipher 제거
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Apache SSL/TLS 설정 점검',
        'category': 'KISA WAS 보안 - 암호화',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1',
        'details': ''
    }
    details = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, ssh_port, ssh_user, ssh_pass, key_filename=ssh_key_file)
        
        # ssl.conf 프로토콜 확인
        cmd = "grep -i 'SSLProtocol' /etc/httpd/conf.d/ssl.conf /etc/apache2/mods-enabled/ssl.conf 2>/dev/null"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        protocol = stdout.read().decode('utf-8', errors='ignore').strip()
        if 'TLSv1.2' not in protocol or 'SSLv3' in protocol:
            result['status'] = 'VULNERABLE'
            details.append("⚠️ 약한 프로토콜 사용 또는 TLS 1.2 미지원")
        details.append(f"SSLProtocol: {protocol}")
        
        ssh.close()
    except Exception as e:
        result['status'] = 'ERROR'
        details.append(f"오류: {str(e)}")
    
    result['details'] = '\n'.join(details)
    return result
