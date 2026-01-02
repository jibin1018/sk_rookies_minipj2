"""KISA DB 보안 가이드 - MS SQL Server 보안 설정
주요 점검: 인증 모드, sa 계정, 포트, 권한, 감사
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22):
    result = {
        'name': 'DB-MSSQL: MS SQL Server 보안 설정',
        'category': 'KISA DB 보안',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'Windows 인증 모드 사용, sa 계정 비활성화, 포트 변경',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, timeout=10)
        
        # SQL Server 프로세스 확인 (Windows)
        details.append("[MSSQL-01] SQL Server 프로세스 확인")
        stdin, stdout, stderr = ssh.exec_command("tasklist | findstr sqlservr.exe || ps aux | grep sqlservr | grep -v grep")
        mssql_process = stdout.read().decode().strip()
        
        if not mssql_process:
            details.append("  • MS SQL Server가 실행되고 있지 않음")
            result['status'] = 'N/A'
            result['details'] = '\n'.join(details)
            ssh.close()
            return result
        
        details.append("  ✓ SQL Server 프로세스 발견")
        
        # 포트 확인 (기본 1433)
        details.append("\n[MSSQL-02] 포트 설정")
        stdin, stdout, stderr = ssh.exec_command("netstat -an | grep 1433 || netstat -an | findstr 1433")
        port_info = stdout.read().decode()
        
        if '1433' in port_info:
            result['vulnerabilities'].append("기본 포트 1433 사용")
            details.append("  ⚠ 주의: 기본 포트(1433) 사용 중 (변경 권장)")
            
            if '0.0.0.0:1433' in port_info or '*:1433' in port_info:
                result['vulnerabilities'].append("모든 IP에서 MSSQL 접근 허용")
                details.append("  ✗ 취약: 모든 인터페이스에서 수신")
                result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: 기본 포트 변경됨")
        
        # sa 계정 확인
        details.append("\n[MSSQL-03] sa 계정 상태")
        details.append("  • 수동 확인 필요: SELECT name, is_disabled FROM sys.server_principals WHERE name = 'sa';")
        details.append("  • sa 계정 비활성화 권장")
        
        # 인증 모드 확인
        details.append("\n[MSSQL-04] 인증 모드")
        details.append("  • 수동 확인 필요: Windows 인증 모드 권장 (혼합 모드 지양)")
        details.append("  • 확인 방법: SSMS > 서버 속성 > 보안 > 서버 인증")
        
        # xp_cmdshell 확인
        details.append("\n[MSSQL-05] xp_cmdshell 설정")
        details.append("  • 수동 확인 필요: EXEC sp_configure 'xp_cmdshell';")
        details.append("  • xp_cmdshell 비활성화 권장 (보안 위험)")
        
        # 네트워크 프로토콜
        details.append("\n[MSSQL-06] 네트워크 프로토콜")
        details.append("  • 수동 확인 필요: TLS 1.2 이상 사용 권장")
        details.append("  • SQL Server 구성 관리자에서 확인")
        
        # 감사 로깅
        details.append("\n[MSSQL-07] 감사 로깅")
        details.append("  • 수동 확인 필요: SQL Server Audit 기능 활성화")
        details.append("  • 로그인 실패, DDL, DML 이벤트 감사 권장")
        
        ssh.close()
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
