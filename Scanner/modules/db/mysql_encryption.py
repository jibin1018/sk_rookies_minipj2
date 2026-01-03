"""
KISA DB 보안 가이드 - MySQL 데이터 암호화 점검
DB-07: 중요 데이터 암호화
DB-08: SSL/TLS 연결 암호화
"""

import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'MySQL 데이터 암호화 점검',
        'category': 'KISA DB 보안 - 암호화',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'SSL/TLS 연결 암호화 설정, 테이블스페이스 암호화, 백업 파일 암호화',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file)
        
        # SSL/TLS 설정 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'have_ssl';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        have_ssl = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if have_ssl and 'YES' in have_ssl:
            details.append("✓ SSL/TLS 지원 활성화")
        else:
            details.append("⚠️ SSL/TLS 지원 비활성화")
            result['vulnerabilities'].append('SSL/TLS 암호화 미지원')
            result['status'] = 'VULNERABLE'
        
        # SSL 필수 연결 설정 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'require_secure_transport';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        require_ssl = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if require_ssl and 'ON' in require_ssl:
            details.append("✓ SSL 필수 연결 설정됨")
        else:
            details.append("⚠️ SSL 필수 연결 미설정 (평문 접속 가능)")
            result['vulnerabilities'].append('SSL 필수 연결 미설정')
            if result['status'] != 'VULNERABLE':
                result['status'] = 'WARN'
        
        # 암호화된 테이블 확인
        cmd = "mysql -u root -e \"SELECT COUNT(*) as encrypted_tables FROM INFORMATION_SCHEMA.TABLES WHERE CREATE_OPTIONS LIKE '%ENCRYPTION%';\""
        stdin, stdout, stderr = ssh.exec_command(
