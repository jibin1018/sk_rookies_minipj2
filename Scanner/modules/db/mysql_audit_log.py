"""
KISA DB 보안 가이드 - MySQL 감사 로그 설정 점검
DB-09: 로그 정책 설정
DB-10: 로그 백업 및 보관
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ssh_utils import safe_ssh_connect, create_error_result
def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'MySQL 감사 로그 설정 점검',
        'category': 'KISA DB 보안 - 로깅 및 모니터링',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '일반 로그 활성화, 에러 로그 활성화, 슬로우 쿼리 로그 설정, 감사 로그 플러그인 활성화',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file)
        
        # General Log 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'general_log';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        general_log = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if general_log and 'ON' in general_log:
            details.append("✓ General Log 활성화")
            
            # 로그 파일 경로 확인
            cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'general_log_file';\""
            stdin, stdout, stderr = ssh.exec_command(cmd)
            log_file = stdout.read().decode('utf-8', errors='ignore').strip()
            if log_file:
                log_path = log_file.split()[-1]
                details.append(f"General Log 경로: {log_path}")
        else:
            details.append("⚠️ General Log 비활성화")
            result['vulnerabilities'].append('일반 로그가 비활성화됨')
            if result['status'] == 'SAFE':
                result['status'] = 'WARN'
        
        # Error Log 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'log_error';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        error_log = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if error_log and error_log.split()[-1] != '':
            error_path = error_log.split()[-1]
            details.append(f"✓ Error Log 활성화: {error_path}")
        else:
            details.append("⚠️ Error Log 경로 미설정")
        
        # Slow Query Log 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'slow_query_log';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        slow_log = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if slow_log and 'ON' in slow_log:
            details.append("✓ Slow Query Log 활성화")
            
            # long_query_time 확인
            cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'long_query_time';\""
            stdin, stdout, stderr = ssh.exec_command(cmd)
            long_query_time = stdout.read().decode('utf-8', errors='ignore').strip()
            if long_query_time:
                time_value = long_query_time.split()[-1]
                details.append(f"Slow Query 기준: {time_value}초")
        else:
            details.append("⚠️ Slow Query Log 비활성화")
        
        # Audit Log 플러그인 확인
        cmd = "mysql -u root -e \"SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME LIKE 'audit%';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        audit_plugin = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if audit_plugin and 'ACTIVE' in audit_plugin:
            details.append("✓ Audit Log 플러그인 활성화")
        else:
            details.append("⚠️ Audit Log 플러그인 비활성화")
            result['vulnerabilities'].append('감사 로그 플러그인 미활성화')
            if result['status'] == 'SAFE':
                result['status'] = 'WARN'
        
        # Binary Log 확인 (복제 및 복구용)
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'log_bin';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        log_bin = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if log_bin and 'ON' in log_bin:
            details.append("✓ Binary Log 활성화")
        else:
            details.append("⚠️ Binary Log 비활성화")
        
        # 로그 파일 권한 확인
        cmd = "ls -la /var/lib/mysql/*.log 2>/dev/null | head -5"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        log_permissions = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if log_permissions:
            details.append(f"로그 파일 권한 확인 필요:\n{log_permissions[:200]}")
        
        ssh.close()
        
    except Exception as e:
        result['status'] = 'ERROR'
        result['details'] = f"오류: {str(e)}"
        return result
    
    result['details'] = '\n'.join(details)
    return result
