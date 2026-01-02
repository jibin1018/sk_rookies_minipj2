"""KISA DB 보안 가이드 - PostgreSQL 보안 설정
주요 점검: 인증, 접근제어, 암호화, 권한, 로깅
"""
import paramiko
import re

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22):
    result = {
        'name': 'DB-PostgreSQL: PostgreSQL 보안 설정',
        'category': 'KISA DB 보안',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'PostgreSQL 인증 강화, 최소 권한 원칙, SSL/TLS 암호화 적용',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, timeout=10)
        
        # PostgreSQL 실행 확인
        details.append("[PostgreSQL-01] 프로세스 확인")
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep postgres | grep -v grep | head -1")
        postgres_process = stdout.read().decode().strip()
        
        if not postgres_process:
            details.append("  • PostgreSQL이 실행되고 있지 않음")
            result['status'] = 'N/A'
            result['details'] = '\n'.join(details)
            ssh.close()
            return result
        
        details.append("  ✓ PostgreSQL 프로세스 발견")
        
        # PostgreSQL 데이터 디렉터리 찾기
        stdin, stdout, stderr = ssh.exec_command(
            "find /var/lib/pgsql /usr/local/pgsql /opt/postgresql -name postgresql.conf 2>/dev/null | head -1 | xargs dirname"
        )
        pg_data_dir = stdout.read().decode().strip()
        
        if not pg_data_dir:
            details.append("  [ERROR] PostgreSQL 데이터 디렉터리를 찾을 수 없음")
            result['status'] = 'ERROR'
            result['details'] = '\n'.join(details)
            ssh.close()
            return result
        
        details.append(f"  데이터 디렉터리: {pg_data_dir}")
        
        # 1. pg_hba.conf 접근 제어 확인
        details.append("\n[PostgreSQL-02] 접근 제어 설정 (pg_hba.conf)")
        pg_hba_path = f"{pg_data_dir}/pg_hba.conf"
        
        stdin, stdout, stderr = ssh.exec_command(f"cat {pg_hba_path} 2>/dev/null | grep -v '^#' | grep -v '^$'")
        pg_hba_content = stdout.read().decode()
        
        if pg_hba_content:
            # trust 인증 확인
            if 'trust' in pg_hba_content.lower():
                result['vulnerabilities'].append("PostgreSQL trust 인증 사용 (무인증)")
                details.append("  ✗ 취약: trust 인증 발견 (비밀번호 없이 접근 가능)")
                result['status'] = 'VULNERABLE'
            
            # md5 대신 scram-sha-256 권장
            if 'md5' in pg_hba_content.lower() and 'scram-sha-256' not in pg_hba_content.lower():
                result['vulnerabilities'].append("약한 인증 방식 (md5)")
                details.append("  ⚠ 주의: md5 인증 사용 (scram-sha-256 권장)")
            
            # 0.0.0.0/0 접근 확인
            if '0.0.0.0/0' in pg_hba_content or '::/0' in pg_hba_content:
                result['vulnerabilities'].append("모든 IP 접근 허용")
                details.append("  ✗ 취약: 모든 IP 대역 접근 허용")
                result['status'] = 'VULNERABLE'
            
            if result['status'] == 'SAFE':
                details.append("  ✓ 양호: 안전한 인증 설정")
        
        # 2. postgresql.conf 보안 설정
        details.append("\n[PostgreSQL-03] 서버 설정 (postgresql.conf)")
        pg_conf_path = f"{pg_data_dir}/postgresql.conf"
        
        stdin, stdout, stderr = ssh.exec_command(f"cat {pg_conf_path} 2>/dev/null | grep -v '^#' | grep -v '^$'")
        pg_conf_content = stdout.read().decode()
        
        if pg_conf_content:
            # SSL 설정
            if "ssl = on" in pg_conf_content or "ssl=on" in pg_conf_content:
                details.append("  ✓ 양호: SSL 암호화 활성화")
            else:
                result['vulnerabilities'].append("PostgreSQL SSL 비활성화")
                details.append("  ✗ 취약: SSL 암호화 비활성화")
                result['status'] = 'VULNERABLE'
            
            # 리스닝 주소
            listen_match = re.search(r"listen_addresses\s*=\s*'([^']+)'", pg_conf_content)
            if listen_match:
                listen_addr = listen_match.group(1)
                if listen_addr == '*' or listen_addr == '0.0.0.0':
                    result['vulnerabilities'].append("모든 인터페이스에서 수신")
                    details.append(f"  ⚠ 주의: listen_addresses = '{listen_addr}'")
                else:
                    details.append(f"  ✓ 양호: 특정 IP만 수신 ({listen_addr})")
        
        # 3. 포트 확인
        details.append("\n[PostgreSQL-04] 포트 설정")
        stdin, stdout, stderr = ssh.exec_command("netstat -tuln | grep 5432 || ss -tuln | grep 5432")
        port_info = stdout.read().decode()
        
        if '5432' in port_info:
            if '0.0.0.0:5432' in port_info or '*:5432' in port_info:
                details.append("  ⚠ 주의: 기본 포트(5432)를 모든 인터페이스에서 수신")
            else:
                details.append("  ✓ 양호: 제한된 인터페이스에서만 수신")
        
        # 4. 로깅 설정
        details.append("\n[PostgreSQL-05] 로깅 설정")
        if 'log_connections = on' in pg_conf_content:
            details.append("  ✓ 양호: 연결 로깅 활성화")
        else:
            details.append("  ⚠ 권장: log_connections 활성화")
        
        # 5. 버전 확인
        details.append("\n[PostgreSQL-06] 버전 확인")
        stdin, stdout, stderr = ssh.exec_command("psql --version 2>/dev/null | head -1")
        version_info = stdout.read().decode().strip()
        
        if version_info:
            details.append(f"  설치 버전: {version_info}")
            version_match = re.search(r'(\d+\.\d+)', version_info)
            if version_match:
                version = float(version_match.group(1))
                if version < 12.0:
                    result['vulnerabilities'].append(f"오래된 PostgreSQL 버전 ({version})")
                    details.append(f"  ⚠ 주의: PostgreSQL {version} - 최신 버전 업그레이드 권장")
        
        ssh.close()
        
    except paramiko.AuthenticationException:
        details.append("  [ERROR] SSH 인증 실패")
        result['status'] = 'ERROR'
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
