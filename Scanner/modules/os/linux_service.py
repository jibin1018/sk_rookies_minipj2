"""
KISA Linux 보안 가이드 - 불필요한 서비스 점검
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Linux 불필요한 서비스 점검',
        'category': 'KISA Linux 보안',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '불필요한 서비스 비활성화, 최소 서비스 운영 원칙',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file, timeout=10)
        
        # 1. 실행 중인 서비스 확인
        details.append("[서비스-1] 실행 중인 서비스 확인")
        
        # systemd 기반
        stdin, stdout, stderr = ssh.exec_command(
            "systemctl list-units --type=service --state=running --no-pager | grep '.service' | awk '{print $1}' | head -20"
        )
        running_services = stdout.read().decode().strip()
        
        if running_services:
            service_count = len(running_services.split('\n'))
            details.append(f"  실행 중인 서비스: {service_count}개")
            for line in running_services.split('\n')[:10]:
                details.append(f"    {line}")
            if service_count > 10:
                details.append(f"    ... 외 {service_count - 10}개")
        
        # 2. 불필요한 서비스 확인
        details.append("\n[서비스-2] 불필요한 서비스 존재 확인")
        
        unnecessary_services = [
            'telnet', 'ftp', 'tftp', 'rsh', 'rlogin', 'rexec',
            'finger', 'echo', 'discard', 'daytime', 'chargen',
            'sendmail', 'nis', 'nfs', 'smb', 'snmp', 'cups',
            'avahi-daemon', 'bluetooth'
        ]
        
        found_services = []
        
        for svc in unnecessary_services:
            stdin, stdout, stderr = ssh.exec_command(
                f"systemctl is-active {svc} 2>/dev/null"
            )
            status = stdout.read().decode().strip()
            
            if status == 'active':
                found_services.append(svc)
        
        if found_services:
            result['vulnerabilities'].append(f"불필요한 서비스 실행 중: {', '.join(found_services)}")
            details.append(f"  ✗ 취약: {', '.join(found_services)}")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: 불필요한 서비스 없음")
        
        # 3. xinetd 서비스 확인
        details.append("\n[서비스-3] xinetd 서비스 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "systemctl is-active xinetd 2>/dev/null"
        )
        xinetd_status = stdout.read().decode().strip()
        
        if xinetd_status == 'active':
            details.append("  xinetd 실행 중")
            
            # xinetd 설정 확인
            stdin, stdout, stderr = ssh.exec_command(
                "ls /etc/xinetd.d/ 2>/dev/null"
            )
            xinetd_services = stdout.read().decode().strip()
            
            if xinetd_services:
                details.append(f"  xinetd 서비스: {xinetd_services.replace(chr(10), ', ')}")
        else:
            details.append("  ✓ xinetd 비활성화")
        
        # 4. 열린 포트 확인
        details.append("\n[서비스-4] 열린 포트 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "sudo netstat -tuln 2>/dev/null || sudo ss -tuln 2>/dev/null | grep LISTEN | head -20"
        )
        open_ports = stdout.read().decode().strip()
        
        if open_ports:
            port_count = len(open_ports.split('\n'))
            details.append(f"  열린 포트: {port_count}개")
            for line in open_ports.split('\n')[:10]:
                details.append(f"    {line}")
            
            # 위험한 포트 확인
            dangerous_ports = ['23', '21', '69', '513', '514', '515']
            for port in dangerous_ports:
                if f':{port} ' in open_ports or f':{port}\t' in open_ports:
                    result['vulnerabilities'].append(f"위험한 포트 열림: {port}")
                    details.append(f"  ✗ 포트 {port} 사용 중")
                    result['status'] = 'VULNERABLE'
        
        # 5. 부팅 시 자동 시작 서비스
        details.append("\n[서비스-5] 부팅 시 자동 시작 서비스")
        
        stdin, stdout, stderr = ssh.exec_command(
            "systemctl list-unit-files --type=service --state=enabled --no-pager | grep '.service' | wc -l"
        )
        enabled_count = stdout.read().decode().strip()
        
        if enabled_count:
            details.append(f"  자동 시작 서비스: {enabled_count}개")
        
        # 6. Apache/Nginx 실행 확인
        details.append("\n[서비스-6] 웹 서버 실행 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "systemctl is-active apache2 nginx 2>/dev/null"
        )
        web_servers = stdout.read().decode().strip()
        
        if 'active' in web_servers:
            details.append("  ✓ 웹 서버 실행 중")
        else:
            details.append("  • 웹 서버 미실행")
        
        # 7. 데이터베이스 실행 확인
        details.append("\n[서비스-7] 데이터베이스 서비스")
        
        db_services = ['mysql', 'mariadb', 'postgresql', 'mongodb', 'redis']
        running_dbs = []
        
        for db in db_services:
            stdin, stdout, stderr = ssh.exec_command(
                f"systemctl is-active {db} 2>/dev/null"
            )
            if stdout.read().decode().strip() == 'active':
                running_dbs.append(db)
        
        if running_dbs:
            details.append(f"  실행 중: {', '.join(running_dbs)}")
        else:
            details.append("  • DB 서비스 미실행")
        
        # 8. cron 서비스 확인
        details.append("\n[서비스-8] cron 서비스 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "systemctl is-active cron 2>/dev/null || systemctl is-active crond 2>/dev/null"
        )
        cron_status = stdout.read().decode().strip()
        
        if cron_status == 'active':
            details.append("  ✓ cron 활성화")
        else:
            details.append("  ⚠ cron 비활성화")
        
        ssh.close()
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result