"""
KISA DB 보안 가이드 - MySQL SQL Injection 방어 설정 점검
DB-19: SQL Injection 방어
DB-20: Prepared Statement 사용
"""

import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'MySQL SQL Injection 방어 설정',
        'category': 'KISA DB 보안 - 애플리케이션 보안',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': 'sql_mode STRICT 설정, NO_AUTO_CREATE_USER 활성화, 에러 메시지 노출 차단',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file)
        
        # SQL Mode 확인 (STRICT mode)
        cmd = "mysql -u root -e \"SELECT @@sql_mode;\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        sql_mode = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if sql_mode:
            details.append(f"SQL Mode: {sql_mode}")
            
            if 'STRICT_TRANS_TABLES' in sql_mode or 'STRICT_ALL_TABLES' in sql_mode:
                details.append("✓ STRICT 모드 활성화")
            else:
                details.append("⚠️ STRICT 모드 비활성화")
                result['vulnerabilities'].append('STRICT 모드 미설정')
                result['status'] = 'VULNERABLE'
            
            if 'NO_AUTO_CREATE_USER' in sql_mode:
                details.append("✓ NO_AUTO_CREATE_USER 설정됨")
            
            if 'NO_ENGINE_SUBSTITUTION' in sql_mode:
                details.append("✓ NO_ENGINE_SUBSTITUTION 설정됨")
        
        # LOAD DATA LOCAL 비활성화 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'local_infile';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        local_infile = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if local_infile and 'OFF' in local_infile:
            details.append("\n✓ local_infile 비활성화 (파일 업로드 차단)")
        else:
            details.append("\n⚠️ local_infile 활성화 (보안 위험)")
            result['vulnerabilities'].append('local_infile이 활성화됨')
            result['status'] = 'VULNERABLE'
        
        # symbolic links 비활성화 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'have_symlink';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        symlink = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if symlink and 'DISABLED' in symlink:
            details.append("✓ Symbolic links 비활성화")
        elif symlink:
            details.append("⚠️ Symbolic links 활성화")
        
        # 에러 메시지 노출 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'log_error_verbosity';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        error_verbosity = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if error_verbosity:
            verbosity_level = error_verbosity.split()[-1]
            details.append(f"\n에러 로그 상세도: {verbosity_level}")
            
            if int(verbosity_level) > 2:
                details.append("⚠️ 에러 메시지가 너무 상세함 (정보 노출 위험)")
        
        # General Query Log 상태 (프로덕션에서는 꺼야 함)
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'general_log';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        general_log = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if general_log and 'ON' in general_log:
            details.append("\n⚠️ General Log 활성화 (성능 저하, SQL 노출)")
            result['vulnerabilities'].append('General Log가 프로덕션에서 활성화됨')
            if result['status'] == 'SAFE':
                result['status'] = 'WARN'
        else:
            details.append("\n✓ General Log 비활성화")
        
        # 안전하지 않은 함수 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'log_bin_trust_function_creators';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        trust_func = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if trust_func and 'ON' in trust_func:
            details.append("\n⚠️ log_bin_trust_function_creators 활성화 (위험한 함수 생성 가능)")
            result['vulnerabilities'].append('신뢰되지 않은 함수 생성 허용')
            if result['status'] == 'SAFE':
                result['status'] = 'WARN'
        
        ssh.close()
        
    except Exception as e:
        result['status'] = 'ERROR'
        result['details'] = f"오류: {str(e)}"
        return result
    
    result['details'] = '\n'.join(details)
    return result
