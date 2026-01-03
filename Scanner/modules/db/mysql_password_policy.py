"""
KISA DB 보안 가이드 - MySQL 패스워드 정책 점검
DB-03: 패스워드 복잡도 설정
DB-04: 패스워드 유효기간 설정
"""

import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'MySQL 패스워드 정책 점검',
        'category': 'KISA DB 보안 - 패스워드 관리',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '패스워드 복잡도 설정, 최소 길이 8자 이상, 유효기간 90일 설정, 재사용 제한',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file)
        
        # validate_password 플러그인 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'validate_password%';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        validate_pwd = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if not validate_pwd or 'validate_password' not in validate_pwd:
            details.append("⚠️ validate_password 플러그인 비활성화")
            result['vulnerabilities'].append('패스워드 복잡도 정책 미설정')
            result['status'] = 'VULNERABLE'
        else:
            details.append("✓ validate_password 플러그인 활성화")
            
            # 패스워드 정책 상세 확인
            if 'validate_password.length' in validate_pwd:
                # MySQL 8.0 이상
                lines = validate_pwd.split('\n')
                for line in lines:
                    if 'validate_password.length' in line:
                        length = line.split()[-1]
                        if int(length) < 8:
                            details.append(f"⚠️ 패스워드 최소 길이: {length}자 (권장: 8자 이상)")
                            result['vulnerabilities'].append('패스워드 최소 길이 부족')
                            result['status'] = 'VULNERABLE'
                        else:
                            details.append(f"✓ 패스워드 최소 길이: {length}자")
                    
                    if 'validate_password.policy' in line:
                        policy = line.split()[-1]
                        details.append(f"패스워드 정책: {policy}")
        
        # 패스워드 유효기간 확인 (default_password_lifetime)
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'default_password_lifetime';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        pwd_lifetime = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if pwd_lifetime and 'default_password_lifetime' in pwd_lifetime:
            lifetime_value = pwd_lifetime.split()[-1]
            if lifetime_value == '0':
                details.append("⚠️ 패스워드 유효기간 미설정")
                result['vulnerabilities'].append('패스워드 유효기간 미설정')
                if result['status'] == 'SAFE':
                    result['status'] = 'WARN'
            else:
                details.append(f"✓ 패스워드 유효기간: {lifetime_value}일")
        
        # 패스워드 재사용 제한 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'password_history';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        pwd_history = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if pwd_history and 'password_history' in pwd_history:
            history_value = pwd_history.split()[-1]
            if history_value == '0':
                details.append("⚠️ 패스워드 재사용 제한 미설정")
                if result['status'] == 'SAFE':
                    result['status'] = 'WARN'
            else:
                details.append(f"✓ 패스워드 재사용 제한: 최근 {history_value}개")
        
        ssh.close()
        
    except Exception as e:
        result['status'] = 'ERROR'
        result['details'] = f"오류: {str(e)}"
        return result
    
    result['details'] = '\n'.join(details)
    return result
