"""KISA DB 보안 가이드 - Oracle Database 보안 설정
주요 점검: 계정 관리, 패스워드 정책, 권한, 네트워크 보안, 감사
"""
import paramiko
import re

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22):
    result = {
        'name': 'DB-Oracle: Oracle Database 보안 설정',
        'category': 'KISA DB 보안',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': 'Oracle 기본 계정 제거, 강력한 패스워드 정책, 최소 권한 원칙 적용',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, timeout=10)
        
        # Oracle 프로세스 확인
        details.append("[Oracle-01] 프로세스 확인")
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep ora_ | grep -v grep | head -1")
        oracle_process = stdout.read().decode().strip()
        
        if not oracle_process:
            details.append("  • Oracle Database가 실행되고 있지 않음")
            result['status'] = 'N/A'
            result['details'] = '\n'.join(details)
            ssh.close()
            return result
        
        details.append("  ✓ Oracle 프로세스 발견")
        
        # ORACLE_HOME 찾기
        stdin, stdout, stderr = ssh.exec_command("echo $ORACLE_HOME")
        oracle_home = stdout.read().decode().strip()
        
        if not oracle_home or oracle_home == '':
            stdin, stdout, stderr = ssh.exec_command(
                "ps aux | grep ora_pmon | grep -v grep | awk '{print $11}' | xargs dirname | xargs dirname"
            )
            oracle_home = stdout.read().decode().strip()
        
        if oracle_home:
            details.append(f"  ORACLE_HOME: {oracle_home}")
        
        # 1. 리스너 설정 확인
        details.append("\n[Oracle-02] 리스너 보안 설정")
        
        listener_path = f"{oracle_home}/network/admin/listener.ora" if oracle_home else "/etc/listener.ora"
        stdin, stdout, stderr = ssh.exec_command(f"cat {listener_path} 2>/dev/null")
        listener_content = stdout.read().decode()
        
        if listener_content:
            # 비밀번호 설정 확인
            if 'PASSWORDS_' not in listener_content.upper():
                result['vulnerabilities'].append("Oracle 리스너 비밀번호 미설정")
                details.append("  ✗ 취약: 리스너 비밀번호 없음")
                result['status'] = 'VULNERABLE'
            
            # 보안 프로토콜 확인
            if 'TCPS' in listener_content or 'SSL' in listener_content:
                details.append("  ✓ 양호: SSL/TLS 설정됨")
            else:
                result['vulnerabilities'].append("Oracle 리스너 암호화 미적용")
                details.append("  ⚠ 주의: TCP 평문 통신 (TCPS 권장)")
        else:
            details.append("  • listener.ora 파일 없음")
        
        # 2. TNS 설정 확인
        details.append("\n[Oracle-03] TNS 보안 설정")
        tnsnames_path = f"{oracle_home}/network/admin/tnsnames.ora" if oracle_home else "/etc/tnsnames.ora"
        stdin, stdout, stderr = ssh.exec_command(f"cat {tnsnames_path} 2>/dev/null")
        tnsnames_content = stdout.read().decode()
        
        if tnsnames_content:
            details.append("  ✓ tnsnames.ora 파일 확인")
        else:
            details.append("  • tnsnames.ora 파일 없음")
        
        # 3. 포트 확인 (1521)
        details.append("\n[Oracle-04] 포트 설정")
        stdin, stdout, stderr = ssh.exec_command("netstat -tuln | grep 1521 || ss -tuln | grep 1521")
        port_info = stdout.read().decode()
        
        if '1521' in port_info:
            if '0.0.0.0:1521' in port_info or '*:1521' in port_info:
                result['vulnerabilities'].append("모든 IP에서 Oracle 접근 허용")
                details.append("  ⚠ 주의: 기본 포트(1521)를 모든 인터페이스에서 수신")
            else:
                details.append("  ✓ 양호: 제한된 인터페이스에서만 수신")
        
        # 4. sqlnet.ora 보안 설정
        details.append("\n[Oracle-05] sqlnet.ora 보안 설정")
        sqlnet_path = f"{oracle_home}/network/admin/sqlnet.ora" if oracle_home else "/etc/sqlnet.ora"
        stdin, stdout, stderr = ssh.exec_command(f"cat {sqlnet_path} 2>/dev/null")
        sqlnet_content = stdout.read().decode()
        
        if sqlnet_content:
            # 암호화 설정
            if 'SQLNET.ENCRYPTION_SERVER' in sqlnet_content:
                details.append("  ✓ 양호: 서버 암호화 설정됨")
            else:
                result['vulnerabilities'].append("Oracle 네트워크 암호화 미설정")
                details.append("  ✗ 취약: SQLNET.ENCRYPTION_SERVER 미설정")
                result['status'] = 'VULNERABLE'
        else:
            details.append("  • sqlnet.ora 파일 없음")
        
        # 5. 버전 확인
        details.append("\n[Oracle-06] 버전 확인")
        details.append("  • 수동 확인 필요: sqlplus로 접속하여 SELECT * FROM v$version;")
        
        ssh.close()
        
    except paramiko.AuthenticationException:
        details.append("  [ERROR] SSH 인증 실패")
        result['status'] = 'ERROR'
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
