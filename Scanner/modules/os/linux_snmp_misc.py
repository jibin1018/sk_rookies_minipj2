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
        
        details.append("\n[U-19] finger 서비스 비활성화")
        
        stdin, stdout, stderr = ssh.exec_command(
            "systemctl is-active finger 2>/dev/null || grep -i '^finger' /etc/inetd.conf /etc/xinetd.d/* 2>/dev/null"
        )
        finger_status = stdout.read().decode().strip()
        
        if finger_status and 'active' in finger_status:
            result['vulnerabilities'].append("finger 서비스 활성화")
            details.append("  ✗ 취약: finger 서비스 실행 중")
            result['status'] = 'VULNERABLE'
        elif finger_status and 'finger' in finger_status.lower():
            result['vulnerabilities'].append("finger 서비스 설정 존재")
            details.append("  ✗ 취약: finger 설정 발견")
            details.append(f"    {finger_status[:200]}")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: finger 서비스 비활성화")
        
        details.append("\n[U-20] Anonymous FTP 비활성화")
        
        stdin, stdout, stderr = ssh.exec_command(
            "systemctl is-active vsftpd proftpd pure-ftpd 2>/dev/null"
        )
        ftp_status = stdout.read().decode().strip()
        
        if 'active' in ftp_status:
            details.append("  FTP 서비스 실행 중")
            
            # vsftpd 설정 확인
            stdin, stdout, stderr = ssh.exec_command(
                "grep -i '^anonymous_enable' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null"
            )
            anon_ftp = stdout.read().decode().strip()
            
            if anon_ftp:
                details.append(f"    {anon_ftp}")
                if 'yes' in anon_ftp.lower():
                    result['vulnerabilities'].append("Anonymous FTP 활성화")
                    details.append("  ✗ 취약: Anonymous FTP 허용")
                    result['status'] = 'VULNERABLE'
                else:
                    details.append("  ✓ 양호: Anonymous FTP 비활성화")
            else:
                details.append("  • Anonymous FTP 설정 확인 불가")
        else:
            details.append("  ✓ 양호: FTP 서비스 비활성화")
        
        details.append("\n[U-21] r 계열 서비스 비활성화 (rsh, rlogin, rexec)")
        
        r_services = ['rsh', 'rlogin', 'rexec', 'rsh.socket', 'rlogin.socket', 'rexec.socket']
        active_r_services = []
        
        for r_svc in r_services:
            stdin, stdout, stderr = ssh.exec_command(
                f"systemctl is-active {r_svc} 2>/dev/null"
            )
            if stdout.read().decode().strip() == 'active':
                active_r_services.append(r_svc)
        
        # xinetd에서도 확인
        stdin, stdout, stderr = ssh.exec_command(
            "grep -E '^(rsh|rlogin|rexec|shell|login)' /etc/inetd.conf /etc/xinetd.d/* 2>/dev/null | grep -v 'disable.*yes'"
        )
        xinetd_r = stdout.read().decode().strip()
        
        if active_r_services:
            result['vulnerabilities'].append(f"r 계열 서비스 활성화: {', '.join(active_r_services)}")
            details.append(f"  ✗ 취약: {', '.join(active_r_services)}")
            result['status'] = 'VULNERABLE'
        elif xinetd_r:
            result['vulnerabilities'].append("r 계열 서비스 xinetd 설정")
            details.append("  ✗ 취약: xinetd에 r 서비스 활성화")
            details.append(f"    {xinetd_r[:200]}")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: r 계열 서비스 모두 비활성화")
        
        details.append("\n[U-22] cron 파일 소유자 및 권한")
        
        cron_files = [
            '/etc/crontab',
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.monthly',
            '/etc/cron.weekly'
        ]
        
        cron_vulnerable = False
        for cron_file in cron_files:
            stdin, stdout, stderr = ssh.exec_command(f"ls -ld {cron_file} 2>/dev/null")
            cron_perm = stdout.read().decode().strip()
            
            if cron_perm:
                parts = cron_perm.split()
                perm = parts[0]
                owner = parts[2]
                
                details.append(f"  {cron_file}:")
                details.append(f"    {cron_perm}")
                
                if owner != 'root':
                    result['vulnerabilities'].append(f"{cron_file} 소유자 부적절")
                    details.append("    ✗ 취약: root 소유 필요")
                    result['status'] = 'VULNERABLE'
                    cron_vulnerable = True
                elif perm[5] == 'w' or perm[8] == 'w':  # group/others write
                    result['vulnerabilities'].append(f"{cron_file} 쓰기 권한 부적절")
                    details.append("    ✗ 취약: group/others 쓰기 금지")
                    result['status'] = 'VULNERABLE'
                    cron_vulnerable = True
        
        if not cron_vulnerable:
            details.append("  ✓ 양호: cron 파일 권한 적절")
        
        details.append("\n[U-23] DoS 취약 서비스 (echo, discard, daytime, chargen)")
        
        dos_services = ['echo', 'discard', 'daytime', 'chargen']
        active_dos = []
        
        for dos_svc in dos_services:
            stdin, stdout, stderr = ssh.exec_command(
                f"systemctl is-active {dos_svc} 2>/dev/null"
            )
            if stdout.read().decode().strip() == 'active':
                active_dos.append(dos_svc)
        
        # xinetd/inetd 확인
        stdin, stdout, stderr = ssh.exec_command(
            "grep -E '^(echo|discard|daytime|chargen)' /etc/inetd.conf /etc/xinetd.d/* 2>/dev/null | grep -v 'disable.*yes'"
        )
        xinetd_dos = stdout.read().decode().strip()
        
        if active_dos:
            result['vulnerabilities'].append(f"DoS 취약 서비스: {', '.join(active_dos)}")
            details.append(f"  ✗ 취약: {', '.join(active_dos)}")
            result['status'] = 'VULNERABLE'
        elif xinetd_dos:
            result['vulnerabilities'].append("DoS 취약 서비스 xinetd 설정")
            details.append("  ✗ 취약: xinetd에 DoS 취약 서비스")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: DoS 취약 서비스 모두 비활성화")
        
        details.append("\n[U-24] NFS 서비스 비활성화")
        
        nfs_services = ['nfs-server', 'nfs', 'nfsd', 'rpcbind']
        active_nfs = []
        
        for nfs_svc in nfs_services:
            stdin, stdout, stderr = ssh.exec_command(
                f"systemctl is-active {nfs_svc} 2>/dev/null"
            )
            if stdout.read().decode().strip() == 'active':
                active_nfs.append(nfs_svc)
        
        if active_nfs:
            details.append(f"  ⚠ 주의: NFS 서비스 실행 중")
            details.append(f"    {', '.join(active_nfs)}")
            details.append("  • 불필요 시 비활성화 권장")
        else:
            details.append("  ✓ 양호: NFS 서비스 비활성화")
        
        details.append("\n[U-25] NFS 접근 통제 (/etc/exports)")
        
        if active_nfs:
            stdin, stdout, stderr = ssh.exec_command("cat /etc/exports 2>/dev/null | grep -v '^#' | grep -v '^$'")
            nfs_exports = stdout.read().decode().strip()
            
            if nfs_exports:
                details.append("  /etc/exports 설정:")
                for line in nfs_exports.split('\n')[:10]:
                    details.append(f"    {line}")
                    
                    # 모든 호스트에 쓰기 허용하는 위험한 설정 확인
                    if '*' in line and 'rw' in line:
                        result['vulnerabilities'].append("NFS 전체 호스트 쓰기 허용")
                        details.append("    ✗ 취약: 모든 호스트에 rw 권한")
                        result['status'] = 'VULNERABLE'
                    
                    # no_root_squash 옵션 확인
                    if 'no_root_squash' in line:
                        result['vulnerabilities'].append("NFS no_root_squash 사용")
                        details.append("    ✗ 취약: no_root_squash 사용")
                        result['status'] = 'VULNERABLE'
            else:
                details.append("  • /etc/exports 비어있음")
        else:
            details.append("  • NFS 서비스 미실행")
        
        details.append("\n[U-26] automountd 제거")
        
        stdin, stdout, stderr = ssh.exec_command(
            "systemctl is-active autofs 2>/dev/null"
        )
        autofs_status = stdout.read().decode().strip()
        
        if autofs_status == 'active':
            result['vulnerabilities'].append("automountd(autofs) 실행 중")
            details.append("  ✗ 취약: autofs 실행 중")
            details.append("  • 불필요 시 비활성화 권장")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: autofs 비활성화")
        
        details.append("\n[U-27] RPC 서비스 확인")
        
        stdin, stdout, stderr = ssh.exec_command("rpcinfo -p 2>/dev/null | tail -n +3")
        rpc_services = stdout.read().decode().strip()
        
        if rpc_services:
            rpc_count = len(rpc_services.split('\n'))
            details.append(f"  RPC 서비스: {rpc_count}개")
            for line in rpc_services.split('\n')[:10]:
                details.append(f"    {line}")
            
            # 위험한 RPC 서비스 확인
            if 'rusersd' in rpc_services or 'walld' in rpc_services or 'sprayd' in rpc_services:
                result['vulnerabilities'].append("불필요한 RPC 서비스 실행")
                details.append("  ✗ 취약: rusersd/walld/sprayd 등 실행 중")
                result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: RPC 서비스 없음")
        
        details.append("\n[U-28] NIS/NIS+ 서비스 비활성화")
        
        nis_services = ['ypserv', 'ypbind', 'nis', 'nisplus']
        active_nis = []
        
        for nis_svc in nis_services:
            stdin, stdout, stderr = ssh.exec_command(
                f"systemctl is-active {nis_svc} 2>/dev/null"
            )
            if stdout.read().decode().strip() == 'active':
                active_nis.append(nis_svc)
        
        if active_nis:
            result['vulnerabilities'].append(f"NIS/NIS+ 서비스: {', '.join(active_nis)}")
            details.append(f"  ✗ 취약: {', '.join(active_nis)} 실행 중")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: NIS/NIS+ 비활성화")
        
        details.append("\n[U-29] tftp, talk 서비스 비활성화")
        
        tftp_talk = ['tftp', 'tftp-server', 'talk', 'ntalk']
        active_tftp_talk = []
        
        for svc in tftp_talk:
            stdin, stdout, stderr = ssh.exec_command(
                f"systemctl is-active {svc} 2>/dev/null"
            )
            if stdout.read().decode().strip() == 'active':
                active_tftp_talk.append(svc)
        
        # xinetd 확인
        stdin, stdout, stderr = ssh.exec_command(
            "grep -E '^(tftp|talk|ntalk)' /etc/inetd.conf /etc/xinetd.d/* 2>/dev/null | grep -v 'disable.*yes'"
        )
        xinetd_tftp = stdout.read().decode().strip()
        
        if active_tftp_talk:
            result['vulnerabilities'].append(f"tftp/talk 서비스: {', '.join(active_tftp_talk)}")
            details.append(f"  ✗ 취약: {', '.join(active_tftp_talk)}")
            result['status'] = 'VULNERABLE'
        elif xinetd_tftp:
            result['vulnerabilities'].append("tftp/talk xinetd 설정")
            details.append("  ✗ 취약: xinetd에 tftp/talk 활성화")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: tftp/talk 비활성화")
        
        details.append("\n[U-60] SSH 프로토콜 버전 및 설정")
        
        stdin, stdout, stderr = ssh.exec_command(
            "grep -E '^Protocol|^PermitEmptyPasswords|^PasswordAuthentication' /etc/ssh/sshd_config"
        )
        ssh_config = stdout.read().decode().strip()
        
        if ssh_config:
            details.append("  SSH 설정:")
            for line in ssh_config.split('\n'):
                details.append(f"    {line}")
                
                if 'Protocol' in line and '1' in line:
                    result['vulnerabilities'].append("SSH Protocol 1 사용")
                    details.append("    ✗ 취약: Protocol 2만 사용 권장")
                    result['status'] = 'VULNERABLE'
                
                if 'PermitEmptyPasswords' in line and 'yes' in line.lower():
                    result['vulnerabilities'].append("SSH 빈 패스워드 허용")
                    details.append("    ✗ 취약: 빈 패스워드 비허용 필요")
                    result['status'] = 'VULNERABLE'
        else:
            details.append("  • SSH 설정 확인 불가")
        
        details.append("\n[U-65] at 파일 소유자 및 권한")
        
        at_files = ['/etc/at.allow', '/etc/at.deny']
        
        for at_file in at_files:
            stdin, stdout, stderr = ssh.exec_command(f"ls -l {at_file} 2>/dev/null")
            at_perm = stdout.read().decode().strip()
            
            if at_perm:
                parts = at_perm.split()
                perm = parts[0]
                owner = parts[2]
                
                details.append(f"  {at_file}:")
                details.append(f"    {at_perm}")
                
                if owner != 'root':
                    result['vulnerabilities'].append(f"{at_file} 소유자 부적절")
                    details.append("    ✗ 취약: root 소유 필요")
                    result['status'] = 'VULNERABLE'
                elif not perm.startswith('-rw-------'):
                    result['vulnerabilities'].append(f"{at_file} 권한 부적절")
                    details.append("    ✗ 취약: 600 권한 필요")
                    result['status'] = 'VULNERABLE'
                else:
                    details.append("    ✓ 양호")
        
        # at.allow 파일 존재 확인
        stdin, stdout, stderr = ssh.exec_command("test -f /etc/at.allow && echo 'exists' || echo 'not found'")
        at_allow_exists = stdout.read().decode().strip()
        
        if at_allow_exists == 'not found':
            details.append("  ⚠ 권장: /etc/at.allow 파일 생성하여 접근 제어")
        
        details.append("\n[U-68] 로그온 경고 메시지 (/etc/motd, /etc/issue)")
        
        banner_files = ['/etc/motd', '/etc/issue', '/etc/issue.net']
        banner_exists = False
        
        for banner_file in banner_files:
            stdin, stdout, stderr = ssh.exec_command(f"cat {banner_file} 2>/dev/null")
            banner_content = stdout.read().decode().strip()
            
            if banner_content:
                banner_exists = True
                details.append(f"  {banner_file}:")
                lines = banner_content.split('\n')[:3]
                for line in lines:
                    details.append(f"    {line[:80]}")
                if len(banner_content.split('\n')) > 3:
                    details.append("    ...")
        
        if banner_exists:
            details.append("  ✓ 양호: 경고 메시지 설정됨")
        else:
            result['vulnerabilities'].append("로그온 경고 메시지 미설정")
            details.append("  ✗ 취약: 경고 메시지 미설정")
            details.append("  • 법적 보호를 위해 경고 메시지 설정 권장")
            result['status'] = 'VULNERABLE'
        
        details.append("\n[U-69] NFS 설정파일 접근 권한")
        
        if active_nfs:
            stdin, stdout, stderr = ssh.exec_command("ls -l /etc/exports 2>/dev/null")
            exports_perm = stdout.read().decode().strip()
            
            if exports_perm:
                parts = exports_perm.split()
                perm = parts[0]
                owner = parts[2]
                
                details.append(f"  {exports_perm}")
                
                if owner != 'root':
                    result['vulnerabilities'].append("/etc/exports 소유자 부적절")
                    details.append("  ✗ 취약: root 소유 필요")
                    result['status'] = 'VULNERABLE'
                elif perm[5] == 'w' or perm[8] == 'w':
                    result['vulnerabilities'].append("/etc/exports 권한 부적절")
                    details.append("  ✗ 취약: 644 이하 권한 필요")
                    result['status'] = 'VULNERABLE'
                else:
                    details.append("  ✓ 양호: 적절한 권한")
        else:
            details.append("  • NFS 미사용")
        
        ssh.close()
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
