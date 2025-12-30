"""
KISA DB 보안 가이드 - MySQL/MariaDB 보안 설정
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22):
    result = {
        'name': 'DB-01~DB-10: MySQL/MariaDB 보안 설정',
        'category': 'KISA 데이터베이스 보안',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': 'DB 계정 권한 최소화, 원격 접속 제한, 취약한 계정 제거, 암호화 적용',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, timeout=10)
        
        # MySQL/MariaDB 설치 확인
        stdin, stdout, stderr = ssh.exec_command("which mysql mysqld 2>/dev/null | head -1")
        mysql_path = stdout.read().decode().strip()
        
        if not mysql_path:
            details.append("  [INFO] MySQL/MariaDB가 설치되지 않음")
            result['status'] = 'N/A'
            ssh.close()
            result['details'] = '\n'.join(details)
            return result
        
        details.append(f"MySQL 경로: {mysql_path}")
        
        # 1. DB-01: 불필요한 샘플 데이터베이스 제거
        details.append("\n[DB-01] 샘플 데이터베이스 확인")
        
        stdin, stdout, stderr = ssh.exec_command("mysql -e 'SHOW DATABASES;' 2>/dev/null")
        databases = stdout.read().decode()
        
        if databases:
            sample_dbs = ['test', 'sample', 'example', 'demo']
            found_samples = [db for db in sample_dbs if db in databases.lower()]
            
            if found_samples:
                result['vulnerabilities'].append(f"샘플 데이터베이스 존재: {', '.join(found_samples)}")
                details.append(f"  ✗ 취약: {', '.join(found_samples)}")
                result['status'] = 'VULNERABLE'
            else:
                details.append("  ✓ 양호: 샘플 DB 없음")
        else:
            details.append("  • MySQL 접속 불가 (인증 필요)")
        
        # 2. DB-02: 익명 계정 제거
        details.append("\n[DB-02] 익명 사용자 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "mysql -e \"SELECT user, host FROM mysql.user WHERE user='';\" 2>/dev/null"
        )
        anonymous = stdout.read().decode().strip()
        
        if anonymous and 'user' in anonymous.lower():
            lines = anonymous.split('\n')
            if len(lines) > 1:  # 헤더 외에 결과 있음
                result['vulnerabilities'].append("익명 사용자 존재")
                details.append("  ✗ 취약: 익명 사용자 발견")
                result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: 익명 사용자 없음")
        
        # 3. DB-03: 패스워드 없는 계정
        details.append("\n[DB-03] 패스워드 없는 계정 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "mysql -e \"SELECT user, host FROM mysql.user WHERE authentication_string='' OR password='';\" 2>/dev/null"
        )
        no_pass = stdout.read().decode().strip()
        
        if no_pass and 'user' in no_pass.lower():
            lines = no_pass.split('\n')
            if len(lines) > 1:
                result['vulnerabilities'].append("패스워드 없는 계정 존재")
                details.append(f"  ✗ 취약: {len(lines)-1}개 계정")
                result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: 모든 계정에 패스워드 설정됨")
        
        # 4. DB-04: 원격 접속 제한
        details.append("\n[DB-04] 원격 접속 설정 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "mysql -e \"SELECT user, host FROM mysql.user WHERE host='%' OR host='0.0.0.0';\" 2>/dev/null"
        )
        remote_access = stdout.read().decode().strip()
        
        if remote_access and 'user' in remote_access.lower():
            lines = remote_access.split('\n')
            if len(lines) > 1:
                result['vulnerabilities'].append("원격 접속 허용 계정 존재")
                details.append(f"  ✗ 취약: 모든 IP에서 접속 가능한 계정")
                result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: 원격 접속 제한됨")
        
        # bind-address 확인
        stdin, stdout, stderr = ssh.exec_command(
            "grep -r 'bind-address' /etc/mysql/ /etc/my.cnf 2>/dev/null"
        )
        bind_address = stdout.read().decode().strip()
        
        if bind_address:
            if '0.0.0.0' in bind_address:
                details.append("  ⚠ bind-address = 0.0.0.0 (모든 IP 허용)")
            elif '127.0.0.1' in bind_address:
                details.append("  ✓ bind-address = 127.0.0.1 (로컬만)")
        
        # 5. DB-05: 불필요한 권한 확인
        details.append("\n[DB-05] SUPER 권한 계정 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "mysql -e \"SELECT user, host FROM mysql.user WHERE Super_priv='Y' AND user!='root';\" 2>/dev/null"
        )
        super_users = stdout.read().decode().strip()
        
        if super_users and 'user' in super_users.lower():
            lines = super_users.split('\n')
            if len(lines) > 1:
                result['vulnerabilities'].append("root 외 SUPER 권한 계정 존재")
                details.append("  ⚠ 주의: 불필요한 SUPER 권한")
        else:
            details.append("  ✓ 양호: SUPER 권한 최소화")
        
        # FILE 권한 확인
        stdin, stdout, stderr = ssh.exec_command(
            "mysql -e \"SELECT user, host FROM mysql.user WHERE File_priv='Y';\" 2>/dev/null"
        )
        file_priv = stdout.read().decode().strip()
        
        if file_priv:
            details.append("  ⚠ FILE 권한을 가진 계정 존재")
        
        # 6. DB-06: MySQL 설정 파일 권한
        details.append("\n[DB-06] MySQL 설정 파일 권한 확인")
        
        config_files = ['/etc/mysql/my.cnf', '/etc/my.cnf', '/etc/mysql/mysql.conf.d/mysqld.cnf']
        
        for config_file in config_files:
            stdin, stdout, stderr = ssh.exec_command(f"ls -l {config_file} 2>/dev/null")
            my_cnf_perm = stdout.read().decode().strip()
            
            if my_cnf_perm:
                details.append(f"  {config_file}: {my_cnf_perm}")
                
                # 644 이상의 권한이면 취약
                if not my_cnf_perm.startswith(('-rw-------', '-r--------', '-rw-r-----')):
                    result['vulnerabilities'].append(f"MySQL 설정 파일 권한 부적절: {config_file}")
                    details.append(f"  ✗ 취약: 과도한 권한 (600 권장)")
                    result['status'] = 'VULNERABLE'
                else:
                    details.append("  ✓ 양호: 설정 파일 권한 적절")
                break
        
        # 7. DB-07: 로그 파일 설정
        details.append("\n[DB-07] 로그 설정 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "grep -E 'log-error|general_log|slow_query_log' /etc/mysql/my.cnf /etc/my.cnf /etc/mysql/mysql.conf.d/*.cnf 2>/dev/null"
        )
        log_config = stdout.read().decode().strip()
        
        if log_config:
            details.append(f"  ✓ 양호: 로그 설정됨")
            for line in log_config.split('\n')[:3]:
                details.append(f"    {line}")
        else:
            result['vulnerabilities'].append("MySQL 로그 미설정")
            details.append("  ⚠ 주의: 로그 설정 확인 필요")
        
        # 8. DB-08: 포트 변경
        details.append("\n[DB-08] MySQL 포트 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "grep '^port' /etc/mysql/my.cnf /etc/my.cnf /etc/mysql/mysql.conf.d/*.cnf 2>/dev/null"
        )
        port_config = stdout.read().decode().strip()
        
        if port_config:
            port = port_config.split('=')[-1].strip()
            if port == '3306':
                details.append(f"  ⚠ 주의: 기본 포트(3306) 사용 중")
            else:
                details.append(f"  ✓ 양호: 비표준 포트({port}) 사용")
        else:
            details.append("  ⚠ 주의: 기본 포트(3306) 사용 추정")
        
        # 9. DB-09: 데이터 디렉터리 권한
        details.append("\n[DB-09] 데이터 디렉터리 권한")
        
        stdin, stdout, stderr = ssh.exec_command(
            "grep '^datadir' /etc/mysql/my.cnf /etc/my.cnf /etc/mysql/mysql.conf.d/*.cnf 2>/dev/null"
        )
        datadir_config = stdout.read().decode().strip()
        
        if datadir_config:
            datadir = datadir_config.split('=')[-1].strip()
            
            stdin, stdout, stderr = ssh.exec_command(f"ls -ld {datadir} 2>/dev/null")
            datadir_perm = stdout.read().decode().strip()
            
            if datadir_perm:
                details.append(f"  데이터 디렉터리: {datadir}")
                details.append(f"  권한: {datadir_perm}")
                
                # mysql 사용자 소유인지 확인
                if 'mysql' not in datadir_perm:
                    details.append("  ⚠ mysql 사용자 소유 아님")
        
        # 10. DB-10: SSL/TLS 암호화
        details.append("\n[DB-10] SSL/TLS 암호화 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "mysql -e \"SHOW VARIABLES LIKE 'have_ssl';\" 2>/dev/null"
        )
        have_ssl = stdout.read().decode().strip()
        
        if 'YES' in have_ssl:
            details.append("  ✓ 양호: SSL 지원됨")
            
            # SSL 필수 설정 확인
            stdin, stdout, stderr = ssh.exec_command(
                "mysql -e \"SELECT user, host, ssl_type FROM mysql.user WHERE ssl_type != '';\" 2>/dev/null"
            )
            ssl_users = stdout.read().decode().strip()
            
            if ssl_users:
                details.append("  ✓ SSL 필수 계정 존재")
            else:
                details.append("  ⚠ SSL 선택적 사용")
        elif 'DISABLED' in have_ssl:
            result['vulnerabilities'].append("SSL 비활성화")
            details.append("  ✗ 취약: SSL 지원 안 함")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  • SSL 상태 확인 불가")
        
        # 11. 추가: local_infile 확인
        details.append("\n[DB-추가] local_infile 설정")
        
        stdin, stdout, stderr = ssh.exec_command(
            "mysql -e \"SHOW VARIABLES LIKE 'local_infile';\" 2>/dev/null"
        )
        local_infile = stdout.read().decode().strip()
        
        if 'ON' in local_infile:
            result['vulnerabilities'].append("local_infile 활성화 (보안 위험)")
            details.append("  ⚠ local_infile = ON (OFF 권장)")
        elif 'OFF' in local_infile:
            details.append("  ✓ local_infile = OFF")
        
        # 12. MySQL 버전 확인
        details.append("\n[DB-버전] MySQL/MariaDB 버전")
        
        stdin, stdout, stderr = ssh.exec_command("mysql -V 2>/dev/null")
        mysql_version = stdout.read().decode().strip()
        
        if mysql_version:
            details.append(f"  {mysql_version}")
            
            # EOL 버전 확인
            if 'Ver 5.5' in mysql_version or 'Ver 5.6' in mysql_version:
                result['vulnerabilities'].append("오래된 MySQL 버전 (EOL)")
                details.append("  ⚠ 지원 종료된 버전 - 업그레이드 필요")
        
        ssh.close()
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result