"""
KISA Linux 보안 가이드 - 로그 관리
로그 설정, 로그 파일 권한, 로그 보존 정책
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ssh_utils import safe_ssh_connect, create_error_result
def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Linux 로그 관리',
        'category': 'KISA Linux 보안',
        'status': 'SAFE',
        'severity': 'LOW',
        'vulnerabilities': [],
        'recommendation': '로그 설정 활성화, 로그 파일 보호, 로그 정기 백업 및 분석',
        'details': ''
    }
    
    details = []
    
    # SSH 연결 (안전)
    ssh, error = safe_ssh_connect(ssh_host, ssh_user, ssh_pass, ssh_port, ssh_key_file)

    if error:
        # SSH 연결 실패 시 ERROR 결과 반환
        module_name = result.get('name', 'Unknown Module')
        return create_error_result(module_name, error, 'ERROR')

    try:
        
        # 1. syslog 데몬 확인
        details.append("[로그-1] syslog 데몬 확인")
        
        syslog_services = ['rsyslog', 'syslog-ng', 'syslogd']
        active_syslog = None
        
        for svc in syslog_services:
            stdin, stdout, stderr = ssh.exec_command(
                f"systemctl is-active {svc} 2>/dev/null"
            )
            status = stdout.read().decode().strip()
            
            if status == 'active':
                active_syslog = svc
                details.append(f"  ✓ {svc} 실행 중")
                break
        
        if not active_syslog:
            result['vulnerabilities'].append("syslog 데몬 미실행")
            details.append("  ✗ 취약: syslog 데몬 없음")
            result['status'] = 'VULNERABLE'
        
        # 2. 주요 로그 파일 존재 확인
        details.append("\n[로그-2] 주요 로그 파일 확인")
        
        log_files = [
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/kern.log',
            '/var/log/cron',
        ]
        
        existing_logs = []
        
        for log_file in log_files:
            stdin, stdout, stderr = ssh.exec_command(f"test -f {log_file} && echo 'exists'")
            exists = stdout.read().decode().strip()
            
            if exists == 'exists':
                existing_logs.append(log_file)
        
        if existing_logs:
            details.append(f"  존재하는 로그: {len(existing_logs)}개")
            for log in existing_logs:
                details.append(f"    {log}")
        else:
            result['vulnerabilities'].append("주요 로그 파일 없음")
            details.append("  ✗ 취약: 로그 파일 없음")
            result['status'] = 'VULNERABLE'
        
        # 3. 로그 파일 권한 확인
        details.append("\n[로그-3] 로그 파일 권한 확인")
        
        for log in existing_logs[:5]:
            stdin, stdout, stderr = ssh.exec_command(f"ls -l {log}")
            log_perm = stdout.read().decode().strip()
            
            if log_perm:
                perm = log_perm.split()[0]
                details.append(f"  {log}: {perm}")
                
                # 640 이하 권한 (타인 읽기 금지)
                if perm[7:10] != '---':
                    result['vulnerabilities'].append(f"로그 파일 권한 부적절: {log}")
                    details.append(f"    ✗ 취약: others 권한 제거 필요")
                    result['status'] = 'VULNERABLE'
        
        # 4. 로그 디렉터리 권한
        details.append("\n[로그-4] /var/log 디렉터리 권한")
        
        stdin, stdout, stderr = ssh.exec_command("ls -ld /var/log")
        varlog_perm = stdout.read().decode().strip()
        
        if varlog_perm:
            details.append(f"  {varlog_perm}")
            
            # 755 이하
            perm = varlog_perm.split()[0]
            if perm[7] == 'w':
                result['vulnerabilities'].append("/var/log others write 권한")
                details.append("  ✗ 취약: others write 제거 필요")
                result['status'] = 'VULNERABLE'
        
        # 5. rsyslog 설정 확인
        details.append("\n[로그-5] rsyslog 설정 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -v '^#' | grep -v '^$' | head -20"
        )
        rsyslog_conf = stdout.read().decode().strip()
        
        if rsyslog_conf:
            details.append("  rsyslog 설정 존재")
            
            # 중요 로그 타입 확인
            log_types = ['auth', 'authpriv', 'kern', 'cron']
            for log_type in log_types:
                if log_type in rsyslog_conf:
                    details.append(f"    ✓ {log_type} 로그 설정됨")
        else:
            details.append("  • rsyslog 설정 확인 불가")
        
        # 6. 원격 로그 전송 확인
        details.append("\n[로그-6] 원격 로그 서버 설정")
        
        stdin, stdout, stderr = ssh.exec_command(
            "grep -r '@@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -v '^#'"
        )
        remote_log = stdout.read().decode().strip()
        
        if remote_log:
            details.append("  ✓ 원격 로그 서버 설정됨")
            details.append(f"    {remote_log.split(':')[-1].strip()[:50]}")
        else:
            details.append("  • 원격 로그 전송 미설정")
            details.append("    (권장: 중앙 로그 서버 사용)")
        
        # 7. logrotate 설정
        details.append("\n[로그-7] logrotate 설정 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "ls /etc/logrotate.d/ 2>/dev/null | wc -l"
        )
        logrotate_count = stdout.read().decode().strip()
        
        if logrotate_count and int(logrotate_count) > 0:
            details.append(f"  ✓ logrotate 설정: {logrotate_count}개 파일")
            
            # syslog logrotate 확인
            stdin, stdout, stderr = ssh.exec_command(
                "cat /etc/logrotate.d/rsyslog 2>/dev/null || cat /etc/logrotate.d/syslog 2>/dev/null | head -10"
            )
            syslog_rotate = stdout.read().decode().strip()
            
            if syslog_rotate:
                details.append("  syslog rotation 설정:")
                for line in syslog_rotate.split('\n')[:5]:
                    if line.strip():
                        details.append(f"    {line}")
        else:
            result['vulnerabilities'].append("logrotate 설정 없음")
            details.append("  ⚠ logrotate 미설정")
        
        # 8. 로그 파일 크기 확인
        details.append("\n[로그-8] 로그 파일 크기")
        
        stdin, stdout, stderr = ssh.exec_command(
            "du -sh /var/log 2>/dev/null"
        )
        log_size = stdout.read().decode().strip()
        
        if log_size:
            details.append(f"  /var/log 전체 크기: {log_size.split()[0]}")
            
            # 큰 로그 파일 확인
            stdin, stdout, stderr = ssh.exec_command(
                "find /var/log -type f -size +100M 2>/dev/null | head -5"
            )
            large_logs = stdout.read().decode().strip()
            
            if large_logs:
                details.append("  100MB 이상 로그:")
                for log in large_logs.split('\n'):
                    details.append(f"    {log}")
        
        # 9. auditd 확인 (Linux 감사)
        details.append("\n[로그-9] auditd (감사 로그) 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "systemctl is-active auditd 2>/dev/null"
        )
        auditd_status = stdout.read().decode().strip()
        
        if auditd_status == 'active':
            details.append("  ✓ auditd 실행 중")
            
            # audit 규칙 확인
            stdin, stdout, stderr = ssh.exec_command(
                "sudo auditctl -l 2>/dev/null | head -10"
            )
            audit_rules = stdout.read().decode().strip()
            
            if audit_rules and 'No rules' not in audit_rules:
                details.append(f"  감사 규칙 설정됨")
            else:
                details.append("  ⚠ 감사 규칙 없음")
        else:
            details.append("  • auditd 미실행")
            details.append("    (권장: auditd 활성화)")
        
        # 10. 로그 보존 기간 확인
        details.append("\n[로그-10] 로그 보존 기간")
        
        stdin, stdout, stderr = ssh.exec_command(
            "grep -r 'rotate\\|maxage' /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null | grep -v '^#' | head -5"
        )
        retention = stdout.read().decode().strip()
        
        if retention:
            details.append("  로그 보존 설정:")
            for line in retention.split('\n')[:3]:
                details.append(f"    {line.split(':')[-1].strip()}")
        else:
            details.append("  • 보존 기간 설정 확인 필요")
        
        # 11. 최근 로그 활동 확인
        details.append("\n[로그-11] 최근 로그 활동")
        
        stdin, stdout, stderr = ssh.exec_command(
            "ls -lt /var/log/*.log 2>/dev/null | head -5"
        )
        recent_logs = stdout.read().decode().strip()
        
        if recent_logs:
            details.append("  최근 업데이트된 로그:")
            for line in recent_logs.split('\n')[:3]:
                details.append(f"    {line}")
        
        # 12. 로그 분석 도구 확인
        details.append("\n[로그-12] 로그 분석 도구")
        
        log_tools = ['logwatch', 'fail2ban', 'aide']
        installed_tools = []
        
        for tool in log_tools:
            stdin, stdout, stderr = ssh.exec_command(f"which {tool} 2>/dev/null")
            if stdout.read().decode().strip():
                installed_tools.append(tool)
        
        if installed_tools:
            details.append(f"  설치된 도구: {', '.join(installed_tools)}")
        else:
            details.append("  • 로그 분석 도구 미설치")
            details.append("    (권장: logwatch, fail2ban 등)")
        
        ssh.close()
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result