"""
KISA DB 보안 가이드 - MySQL 권한 및 역할 점검
DB-15: 과도한 권한 제거
DB-16: GRANT OPTION 제한
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ssh_utils import safe_ssh_connect, create_error_result
def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'MySQL 권한 및 역할 점검',
        'category': 'KISA DB 보안 - 권한 관리',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': 'ALL PRIVILEGES 제거, GRANT OPTION 제한, FILE 권한 제한, SUPER 권한 최소화',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file)
        
        # ALL PRIVILEGES 권한 확인
        cmd = "mysql -u root -e \"SELECT User, Host FROM mysql.user WHERE Select_priv='Y' AND Insert_priv='Y' AND Update_priv='Y' AND Delete_priv='Y' AND Create_priv='Y' AND Drop_priv='Y';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        all_priv_users = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if all_priv_users and len(all_priv_users.split('\n')) > 1:
            user_count = len(all_priv_users.split('\n')) - 1
            details.append(f"⚠️ 전체 권한 보유 계정: {user_count}개")
            if user_count > 2:
                result['vulnerabilities'].append(f'{user_count}개 계정이 ALL PRIVILEGES 보유')
                result['status'] = 'VULNERABLE'
            else:
                details.append("전체 권한은 root 등 필수 계정만 보유 권장")
        else:
            details.append("✓ 전체 권한 보유 계정 최소화됨")
        
        # GRANT OPTION 권한 확인
        cmd = "mysql -u root -e \"SELECT User, Host FROM mysql.user WHERE Grant_priv='Y';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        grant_users = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if grant_users and len(grant_users.split('\n')) > 1:
            grant_count = len(grant_users.split('\n')) - 1
            details.append(f"\n⚠️ GRANT OPTION 권한 보유 계정: {grant_count}개")
            if grant_count > 1:
                result['vulnerabilities'].append(f'{grant_count}개 계정이 GRANT OPTION 보유')
                if result['status'] == 'SAFE':
                    result['status'] = 'WARN'
            
            # GRANT OPTION 보유 계정 목록
            details.append("GRANT OPTION 보유 계정:")
            for line in grant_users.split('\n')[1:]:
                if line.strip():
                    details.append(f"  - {line}")
        else:
            details.append("✓ GRANT OPTION 권한 최소화됨")
        
        # FILE 권한 확인 (매우 위험)
        cmd = "mysql -u root -e \"SELECT User, Host FROM mysql.user WHERE File_priv='Y';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        file_priv_users = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if file_priv_users and len(file_priv_users.split('\n')) > 1:
            file_count = len(file_priv_users.split('\n')) - 1
            details.append(f"\n⚠️ FILE 권한 보유 계정: {file_count}개")
            result['vulnerabilities'].append(f'{file_count}개 계정이 FILE 권한 보유 (파일 읽기/쓰기 가능)')
            result['status'] = 'VULNERABLE'
            
            details.append("FILE 권한 보유 계정:")
            for line in file_priv_users.split('\n')[1:]:
                if line.strip():
                    details.append(f"  - {line}")
        else:
            details.append("✓ FILE 권한 없음 (안전)")
        
        # SUPER 권한 확인
        cmd = "mysql -u root -e \"SELECT User, Host FROM mysql.user WHERE Super_priv='Y';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        super_users = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if super_users and len(super_users.split('\n')) > 1:
            super_count = len(super_users.split('\n')) - 1
            details.append(f"\n⚠️ SUPER 권한 보유 계정: {super_count}개")
            if super_count > 2:
                result['vulnerabilities'].append(f'{super_count}개 계정이 SUPER 권한 보유')
                if result['status'] == 'SAFE':
                    result['status'] = 'WARN'
        
        # PROCESS 권한 확인 (프로세스 조회 가능)
        cmd = "mysql -u root -e \"SELECT User, Host FROM mysql.user WHERE Process_priv='Y';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        process_users = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if process_users and len(process_users.split('\n')) > 1:
            process_count = len(process_users.split('\n')) - 1
            details.append(f"\nPROCESS 권한 보유 계정: {process_count}개")
        
        # SHUTDOWN 권한 확인 (매우 위험)
        cmd = "mysql -u root -e \"SELECT User, Host FROM mysql.user WHERE Shutdown_priv='Y';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        shutdown_users = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if shutdown_users and len(shutdown_users.split('\n')) > 1:
            shutdown_count = len(shutdown_users.split('\n')) - 1
            if shutdown_count > 1:
                details.append(f"\n⚠️ SHUTDOWN 권한 보유 계정: {shutdown_count}개")
                result['vulnerabilities'].append(f'{shutdown_count}개 계정이 SHUTDOWN 권한 보유')
                result['status'] = 'VULNERABLE'
        
        # 권한 요약
        cmd = "mysql -u root -e \"SELECT User, Host, Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv FROM mysql.user;\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        all_privileges = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if all_privileges:
            details.append(f"\n전체 계정 권한 현황:\n{all_privileges[:500]}")
        
        ssh.close()
        
    except Exception as e:
        result['status'] = 'ERROR'
        result['details'] = f"오류: {str(e)}"
        return result
    
    result['details'] = '\n'.join(details)
    return result
