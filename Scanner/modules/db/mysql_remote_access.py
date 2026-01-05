"""
KISA DB 보안 가이드 - MySQL 원격 접속 제한 점검
DB-05: 불필요한 원격 접속 차단
DB-06: bind-address 설정
"""

import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'MySQL 원격 접속 제한 점검',
        'category': 'KISA DB 보안 - 네트워크 접근 제어',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': 'bind-address를 127.0.0.1로 설정, 필요한 IP만 접근 허용, 방화벽 설정',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file)
        
        # bind-address 설정 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'bind_address';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        bind_address = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if bind_address:
            if '0.0.0.0' in bind_address or '*' in bind_address:
                details.append("⚠️ bind-address가 모든 IP에서 접속 허용 (0.0.0.0)")
                result['vulnerabilities'].append('MySQL이 모든 네트워크 인터페이스에서 접속 허용')
                result['status'] = 'VULNERABLE'
            elif '127.0.0.1' in bind_address or 'localhost' in bind_address:
                details.append("✓ bind-address가 localhost로 제한됨")
            else:
                bind_ip = bind_address.split()[-1]
                details.append(f"✓ bind-address: {bind_ip}")
        
        # MySQL 포트 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'port';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        port_info = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if port_info:
            mysql_port = port_info.split()[-1]
            details.append(f"MySQL 포트: {mysql_port}")
            
            # 외부에서 접근 가능한지 netstat으로 확인
            cmd = f"netstat -an | grep {mysql_port} | grep LISTEN"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            netstat_result = stdout.read().decode('utf-8', errors='ignore').strip()
            
            if netstat_result:
                if '0.0.0.0' in netstat_result or ':::' in netstat_result:
                    details.append(f"⚠️ MySQL 포트({mysql_port})가 외부에 노출됨")
                    if result['status'] != 'VULNERABLE':
                        result['status'] = 'WARN'
        
        # 원격 접속 가능한 계정 확인
        cmd = "mysql -u root -e \"SELECT User, Host FROM mysql.user WHERE Host NOT IN ('localhost', '127.0.0.1', '::1');\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        remote_accounts = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if remote_accounts and len(remote_accounts.split('\n')) > 1:
            remote_count = len(remote_accounts.split('\n')) - 1
            details.append(f"⚠️ 원격 접속 가능한 계정: {remote_count}개")
            result['vulnerabilities'].append(f'{remote_count}개 계정이 원격 접속 가능')
            if result['status'] == 'SAFE':
                result['status'] = 'WARN'
        else:
            details.append("✓ 원격 접속 가능한 계정 없음")
        
        # skip-networking 설정 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'skip_networking';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        skip_net = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if skip_net and 'ON' in skip_net:
            details.append("✓ skip-networking 활성화 (네트워크 접속 차단)")
        
        ssh.close()
        
    except Exception as e:
        result['status'] = 'ERROR'
        result['details'] = f"오류: {str(e)}"
        return result
    
    result['details'] = '\n'.join(details)
    return result
