"""
KISA DB 보안 가이드 - MySQL 백업 설정 점검
DB-17: 정기 백업 설정
DB-18: 백업 파일 암호화 및 보관
"""

import paramiko
import re

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
        
        # Binary Log 활성화 확인 (Point-in-time recovery용)
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'log_bin';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        log_bin = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if log_bin and 'ON' in log_bin:
            details.append("✓ Binary Log 활성화 (Point-in-time 복구 가능)")
        else:
            details.append("⚠️ Binary Log 비활성화")
            result['vulnerabilities'].append('Binary Log가 비활성화되어 증분 백업 불가')
            result['status'] = 'VULNERABLE'
        
        # Binary Log 보관 기간 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'expire_logs_days';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        expire_days = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if expire_days:
            days = expire_days.split()[-1]
            if days == '0':
                details.append("⚠️ Binary Log 자동 삭제 미설정 (무한 보관)")
                if result['status'] == 'SAFE':
                    result['status'] = 'WARN'
            else:
                details.append(f"✓ Binary Log 보관 기간: {days}일")
        
        # 백업 디렉토리 확인
        backup_dirs = [
            '/var/backups/mysql',
            '/backup/mysql',
            '/home/backup/mysql',
            '/data/backup/mysql'
        ]
        
        found_backup = False
        for backup_dir in backup_dirs:
            cmd = f"ls -lh {backup_dir}/*.sql* 2>/dev/null | tail -5"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            backup_files = stdout.read().decode('utf-8', errors='ignore').strip()
            
            if backup_files and '.sql' in backup_files:
                found_backup = True
                details.append(f"\n✓ 백업 파일 발견: {backup_dir}")
                details.append(f"최근 백업 파일:\n{backup_files}")
                
                # 백업 파일 날짜 확인
                lines = backup_files.split('\n')
                if lines:
                    latest_file = lines[-1]
                    details.append(f"최신 백업: {latest_file}")
                break
        
        if not found_backup:
            details.append("\n⚠️ 백업 파일을 찾을 수 없음")
            result['vulnerabilities'].append('백업 파일이 존재하지 않음')
            result['status'] = 'VULNERABLE'
        
        # cron 백업 스케줄 확인
        cmd = "crontab -l 2>/dev/null | grep -i 'mysqldump\\|backup\\|mysql'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        cron_backup = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if cron_backup:
            details.append(f"\n✓ Cron 백업 스케줄 설정됨:\n{cron_backup}")
        else:
            details.append("\n⚠️ Cron 백업 스케줄 미설정")
            result['vulnerabilities'].append('자동 백업 스케줄이 설정되지 않음')
            if result['status'] == 'SAFE':
                result['status'] = 'WARN'
        
        # 백업 파일 권한 확인
        for backup_dir in backup_dirs:
            cmd = f"ls -la {backup_dir}/*.sql* 2>/dev/null | head -3"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            backup_perms = stdout.read().decode('utf-8', errors='ignore').strip()
            
            if backup_perms:
                details.append(f"\n백업 파일 권한:\n{backup_perms}")
                
                # 너무 개방적인 권한 확인
                if 'rw-rw-rw-' in backup_perms or 'rwxrwxrwx' in backup_perms:
                    details.append("⚠️ 백업 파일 권한이 너무 개방적")
                    result['vulnerabilities'].append('백업 파일 권한이 안전하지 않음')
                    if result['status'] == 'SAFE':
                        result['status'] = 'WARN'
                break
        
        # mysqldump 설치 확인
        cmd = "which mysqldump"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        mysqldump_path = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if mysqldump_path:
            details.append(f"\n✓ mysqldump 설치됨: {mysqldump_path}")
        else:
            details.append("\n⚠️ mysqldump가 설치되지 않음")
        
        # 최근 백업 실행 로그 확인
        cmd = "grep -i 'mysqldump\\|backup' /var/log/syslog /var/log/messages 2>/dev/null | tail -5"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        backup_logs = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if backup_logs:
            details.append(f"\n최근 백업 로그:\n{backup_logs[:300]}")
        
        # 백업 용
