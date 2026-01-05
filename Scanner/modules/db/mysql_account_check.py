"""
KISA DB 보안 가이드 - MySQL 계정 및 권한 점검
DB-01: 불필요한 계정 제거
DB-02: 계정 권한 최소화
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ssh_utils import safe_ssh_connect, create_error_result
def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'MySQL 계정 및 권한 점검',
        'category': 'KISA DB 보안 - 계정 관리',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': 'root 계정 원격 접속 차단, 익명 사용자 삭제, test DB 삭제, 불필요한 계정 제거',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file)
        
        # MySQL root 원격 접속 확인
        cmd = "mysql -u root -e \"SELECT User, Host FROM mysql.user WHERE User='root' AND Host!='localhost';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        root_remote = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if root_remote and len(root_remote.split('\n')) > 1:
            details.append("⚠️ root 계정 원격 접속 허용됨")
            result['vulnerabilities'].append('root 계정이 원격에서 접속 가능')
            result['status'] = 'VULNERABLE'
        else:
            details.append("✓ root 계정 원격 접속 차단됨")
        
        # 익명 사용자 확인
        cmd = "mysql -u root -e \"SELECT User, Host FROM mysql.user WHERE User='';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        anonymous_users = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if anonymous_users and len(anonymous_users.split('\n')) > 1:
            details.append("⚠️ 익명 사용자 존재")
            result['vulnerabilities'].append('익명 사용자가 존재함')
            result['status'] = 'VULNERABLE'
        else:
            details.append("✓ 익명 사용자 없음")
        
        # test 데이터베이스 확인
        cmd = "mysql -u root -e \"SHOW DATABASES LIKE 'test';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        test_db = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if test_db and 'test' in test_db:
            details.append("⚠️ test 데이터베이스 존재")
            result['vulnerabilities'].append('test 데이터베이스가 존재함')
            if result['status'] != 'VULNERABLE':
                result['status'] = 'WARN'
        else:
            details.append("✓ test 데이터베이스 없음")
        
        # 전체 계정 목록 확인
        cmd = "mysql -u root -e \"SELECT User, Host, authentication_string FROM mysql.user;\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        all_users = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if all_users:
            user_count = len(all_users.split('\n')) - 1
            details.append(f"전체 MySQL 계정 수: {user_count}개")
        
        ssh.close()
        
    except Exception as e:
        result['status'] = 'ERROR'
        result['details'] = f"오류: {str(e)}"
        return result
    
    result['details'] = '\n'.join(details)
    return result
