"""KISA DB 보안 가이드 - MongoDB 보안 설정
주요 점검: 인증, 권한, 네트워크 노출, 암호화
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22):
    result = {
        'name': 'DB-MongoDB: MongoDB 보안 설정',
        'category': 'KISA DB 보안',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'MongoDB 인증 활성화, bind_ip 제한, TLS/SSL 사용',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, timeout=10)
        
        # MongoDB 프로세스 확인
        details.append("[MongoDB-01] 프로세스 확인")
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep mongod | grep -v grep")
        mongo_process = stdout.read().decode().strip()
        
        if not mongo_process:
            details.append("  • MongoDB가 실행되고 있지 않음")
            result['status'] = 'N/A'
            result['details'] = '\n'.join(details)
            ssh.close()
            return result
        
        details.append("  ✓ MongoDB 프로세스 발견")
        
        # MongoDB 설정 파일 찾기
        details.append("\n[MongoDB-02] 설정 파일 확인")
        stdin, stdout, stderr = ssh.exec_command(
            "find /etc /usr/local -name mongod.conf 2>/dev/null | head -1"
        )
        config_path = stdout.read().decode().strip()
        
        if not config_path:
            details.append("  ⚠ 주의: mongod.conf 파일을 찾을 수 없음")
            config_path = "/etc/mongod.conf"
        else:
            details.append(f"  설정 파일: {config_path}")
        
        # 1. 인증 활성화 여부
        details.append("\n[MongoDB-03] 인증 설정")
        stdin, stdout, stderr = ssh.exec_command(f"cat {config_path} 2>/dev/null | grep -i authorization")
        auth_config = stdout.read().decode()
        
        if 'authorization: enabled' in auth_config or 'authorization:enabled' in auth_config:
            details.append("  ✓ 양호: 인증 활성화됨")
        else:
            result['vulnerabilities'].append("MongoDB 인증 비활성화")
            details.append("  ✗ 취약: 인증 비활성화 (무인증 접근 가능)")
            result['status'] = 'VULNERABLE'
        
        # 2. bind_ip 설정 확인
        details.append("\n[MongoDB-04] 네트워크 바인딩")
        stdin, stdout, stderr = ssh.exec_command(f"cat {config_path} 2>/dev/null | grep bindIp")
        bind_config = stdout.read().decode()
        
        if bind_config:
            if '0.0.0.0' in bind_config or '::' in bind_config:
                result['vulnerabilities'].append("모든 IP에서 MongoDB 접근 허용")
                details.append("  ✗ 취약: bindIp: 0.0.0.0 (모든 인터페이스)")
                result['status'] = 'VULNERABLE'
            elif '127.0.0.1' in bind_config:
                details.append("  ✓ 양호: localhost만 수신")
            else:
                details.append(f"  ✓ 양호: 특정 IP만 수신")
        else:
            details.append("  • bindIp 설정 없음 (기본값 확인 필요)")
        
        # 3. 포트 확인 (27017)
        details.append("\n[MongoDB-05] 포트 설정")
        stdin, stdout, stderr = ssh.exec_command("netstat -tuln | grep 27017 || ss -tuln | grep 27017")
        port_info = stdout.read().decode()
        
        if '27017' in port_info:
            if '0.0.0.0:27017' in port_info:
                details.append("  ⚠ 주의: 기본 포트(27017)를 모든 인터페이스에서 수신")
            else:
                details.append("  ✓ 양호: 제한된 인터페이스에서만 수신")
        
        # 4. TLS/SSL 설정
        details.append("\n[MongoDB-06] TLS/SSL 암호화")
        stdin, stdout, stderr = ssh.exec_command(f"cat {config_path} 2>/dev/null | grep -i 'tls\|ssl'")
        tls_config = stdout.read().decode()
        
        if 'TLSMode' in tls_config or 'sslMode' in tls_config:
            details.append("  ✓ 양호: TLS/SSL 설정됨")
        else:
            result['vulnerabilities'].append("MongoDB TLS/SSL 미설정")
            details.append("  ✗ 취약: 암호화 비활성화 (평문 통신)")
            result['status'] = 'VULNERABLE'
        
        # 5. 로그 설정
        details.append("\n[MongoDB-07] 로깅 설정")
        stdin, stdout, stderr = ssh.exec_command(f"cat {config_path} 2>/dev/null | grep -i 'systemLog\|log'")
        log_config = stdout.read().decode()
        
        if log_config:
            details.append("  ✓ 양호: 로깅 설정됨")
        else:
            details.append("  ⚠ 권장: 로깅 활성화")
        
        # 6. 버전 확인
        details.append("\n[MongoDB-08] 버전 확인")
        stdin, stdout, stderr = ssh.exec_command("mongod --version 2>/dev/null | head -1")
        version_info = stdout.read().decode().strip()
        
        if version_info:
            details.append(f"  설치 버전: {version_info}")
        else:
            details.append("  • 버전 정보 확인 불가")
        
        ssh.close()
        
    except paramiko.AuthenticationException:
        details.append("  [ERROR] SSH 인증 실패")
        result['status'] = 'ERROR'
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
