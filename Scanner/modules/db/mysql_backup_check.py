"""
KISA DB 보안 가이드 - MySQL 백업 설정 점검
DB-17: 정기 백업 설정
DB-18: 백업 파일 암호화 및 보관
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ssh_utils import safe_ssh_connect, create_error_result
def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'MySQL 백업 설정 점검',
        'category': 'KISA DB 보안 - 백업 및 복구',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '정기 백업 스케줄 설정, 백업 파일 암호화, 원격지 백업, 복구 테스트',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file)
        
        # Binary Log 활성화 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'log_bin';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        log_bin = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if log_bin and 'ON' in log_bin:
            details.append("✓ Binary Log 활성화")
        else:
            details.append("⚠️ Binary Log 비활성화")
            result['vulnerabilities'].append('Binary Log 비활성화')
            result['status'] = 'VULNERABLE'
        
        # 백업 디렉토리 확인
        backup_dirs = ['/var/backups/mysql', '/backup/mysql', '/home/backup/mysql']
        found_backup = False
        
        for backup_dir in backup_dirs:
            cmd = f"ls -lh {backup_dir}/*.sql* 2>/dev/null | tail -5"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            backup_files = stdout.read().decode('utf-8', errors='ignore').strip()
            
            if backup_files and '.sql' in backup_files:
                found_backup = True
                details.append(f"\n✓ 백업 파일 발견: {backup_dir}")
                details.append(f"최근 백업:\n{backup_files[:200]}")
                break
        
        if not found_backup:
            details.append("\n⚠️ 백업 파일 없음")
            result['vulnerabilities'].append('백업 파일 미발견')
            result['status'] = 'VULNERABLE'
        
        # cron 백업 스케줄 확인
        cmd = "crontab -l 2>/dev/null | grep -i mysqldump"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        cron_backup = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if cron_backup:
            details.append(f"\n✓ 자동 백업 스케줄:\n{cron_backup}")
        else:
            details.append("\n⚠️ 자동 백업 미설정")
            result['vulnerabilities'].append('자동 백업 스케줄 미설정')
            if result['status'] == 'SAFE':
                result['status'] = 'WARN'
        
        ssh.close()
        
    except Exception as e:
        result['status'] = 'ERROR'
        result['details'] = f"오류: {str(e)}"
        return result
    
    result['details'] = '\n'.join(details)
    return result
