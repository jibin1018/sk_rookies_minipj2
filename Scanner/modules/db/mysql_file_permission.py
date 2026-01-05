"""
KISA DB 보안 가이드 - MySQL 파일 및 디렉토리 권한 점검
DB-11: 데이터 파일 권한 설정
DB-12: 설정 파일 권한 설정
"""

import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'MySQL 파일 및 디렉토리 권한 점검',
        'category': 'KISA DB 보안 - 파일 권한 관리',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'my.cnf 권한 600 설정, 데이터 디렉토리 권한 700 설정, 로그 파일 권한 640 설정',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file)
        
        # my.cnf 설정 파일 권한 확인
        config_files = [
            '/etc/my.cnf',
            '/etc/mysql/my.cnf',
            '/etc/mysql/mysql.conf.d/mysqld.cnf',
            '/usr/local/mysql/etc/my.cnf'
        ]
        
        for config_file in config_files:
            cmd = f"ls -la {config_file} 2>/dev/null"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            file_info = stdout.read().decode('utf-8', errors='ignore').strip()
            
            if file_info and 'No such file' not in file_info:
                details.append(f"설정 파일: {config_file}")
                
                # 권한 확인 (644, 640, 600 이외는 경고)
                if file_info:
                    permissions = file_info.split()[0]
                    if 'rw-------' in permissions or '600' in permissions:
                        details.append(f"✓ {config_file} 권한: 600 (안전)")
                    elif 'rw-r-----' in permissions or '640' in permissions:
                        details.append(f"✓ {config_file} 권한: 640")
                    elif 'rw-r--r--' in permissions or '644' in permissions:
                        details.append(f"⚠️ {config_file} 권한: 644 (타 사용자 읽기 가능)")
                        result['vulnerabilities'].append(f'{config_file} 권한이 너무 개방적')
                        if result['status'] == 'SAFE':
                            result['status'] = 'WARN'
                    else:
                        details.append(f"⚠️ {config_file} 권한: {permissions} (점검 필요)")
                        result['vulnerabilities'].append(f'{config_file} 권한 설정 부적절')
                        result['status'] = 'VULNERABLE'
                
                # 소유자 확인
                if 'root' not in file_info.split()[2]:
                    details.append(f"⚠️ {config_file} 소유자가 root가 아님")
        
        # MySQL 데이터 디렉토리 권한 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'datadir';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        datadir_output = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if datadir_output:
            datadir = datadir_output.split()[-1]
            details.append(f"\nMySQL 데이터 디렉토리: {datadir}")
            
            cmd = f"ls -ld {datadir}"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            datadir_info = stdout.read().decode('utf-8', errors='ignore').strip()
            
            if datadir_info:
                permissions = datadir_info.split()[0]
                owner = datadir_info.split()[2]
                
                if 'drwx------' in permissions or '700' in permissions:
                    details.append(f"✓ 데이터 디렉토리 권한: 700 (안전)")
                elif 'drwxr-x---' in permissions or '750' in permissions:
                    details.append(f"✓ 데이터 디렉토리 권한: 750")
                else:
                    details.append(f"⚠️ 데이터 디렉토리 권한: {permissions} (취약)")
                    result['vulnerabilities'].append(f'데이터 디렉토리 권한이 너무 개방적')
                    result['status'] = 'VULNERABLE'
                
                details.append(f"소유자: {owner}")
        
        # 로그 파일 권한 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE '%log_error%';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        log_file_output = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if log_file_output:
            for line in log_file_output.split('\n'):
                if 'log_error' in line and '/' in line:
                    log_path = line.split()[-1]
                    
                    cmd = f"ls -la {log_path} 2>/dev/null"
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    log_info = stdout.read().decode('utf-8', errors='ignore').strip()
                    
                    if log_info:
                        details.append(f"\n로그 파일: {log_path}")
                        permissions = log_info.split()[0]
                        
                        if 'rw-------' in permissions or 'rw-r-----' in permissions:
                            details.append(f"✓ 로그 파일 권한 안전: {permissions}")
                        else:
                            details.append(f"⚠️ 로그 파일 권한: {permissions}")
        
        # /var/lib/mysql 소유자 확인
        cmd = "ls -ld /var/lib/mysql 2>/dev/null"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        mysql_dir_info = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if mysql_dir_info:
            owner = mysql_dir_info.split()[2]
            if owner != 'mysql':
                details.append(f"\n⚠️ /var/lib/mysql 소유자: {owner} (권장: mysql)")
                result['vulnerabilities'].append('/var/lib/mysql 소유자가 mysql이 아님')
                if result['status'] == 'SAFE':
                    result['status'] = 'WARN'
        
        ssh.close()
        
    except Exception as e:
        result['status'] = 'ERROR'
        result['details'] = f"오류: {str(e)}"
        return result
    
    result['details'] = '\n'.join(details)
    return result
