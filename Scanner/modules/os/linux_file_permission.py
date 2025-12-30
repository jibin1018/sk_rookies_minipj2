"""
KISA Linux 보안 가이드 - U-44: 파일 및 디렉터리 권한 설정
주요 시스템 파일 권한, world-writable 파일, SetUID/SetGID 파일 점검
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22):
    result = {
        'name': 'U-44: Linux 파일 및 디렉터리 권한',
        'category': 'KISA Linux 보안',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '중요 파일 권한 적절히 설정, world-writable 파일 제거, SetUID 최소화',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, timeout=10)
        
        # 1. /etc/passwd 권한 확인
        details.append("[파일권한-1] /etc/passwd 권한 확인")
        
        stdin, stdout, stderr = ssh.exec_command("ls -l /etc/passwd")
        passwd_perm = stdout.read().decode().strip()
        
        if passwd_perm:
            details.append(f"  {passwd_perm}")
            
            # 644 (-rw-r--r--) 권한이어야 함
            if not passwd_perm.startswith('-rw-r--r--'):
                result['vulnerabilities'].append("/etc/passwd 권한 부적절")
                details.append("  ✗ 취약: 644 권한 필요")
                result['status'] = 'VULNERABLE'
            else:
                details.append("  ✓ 양호: 644 권한")
        
        # 2. /etc/shadow 권한 확인
        details.append("\n[파일권한-2] /etc/shadow 권한 확인")
        
        stdin, stdout, stderr = ssh.exec_command("sudo ls -l /etc/shadow 2>/dev/null")
        shadow_perm = stdout.read().decode().strip()
        
        if shadow_perm:
            details.append(f"  {shadow_perm}")
            
            # 400 또는 600 권한
            if not shadow_perm.startswith(('-r--------', '-rw-------')):
                result['vulnerabilities'].append("/etc/shadow 권한 부적절")
                details.append("  ✗ 취약: 400 또는 600 권한 필요")
                result['status'] = 'VULNERABLE'
            else:
                details.append("  ✓ 양호: 적절한 권한")
        else:
            details.append("  • /etc/shadow 확인 불가")
        
        # 3. /etc/hosts 권한
        details.append("\n[파일권한-3] /etc/hosts 권한 확인")
        
        stdin, stdout, stderr = ssh.exec_command("ls -l /etc/hosts")
        hosts_perm = stdout.read().decode().strip()
        
        if hosts_perm:
            details.append(f"  {hosts_perm}")
            
            # 644 이하 권한 (others write 금지)
            if hosts_perm[8] == 'w':  # others write
                result['vulnerabilities'].append("/etc/hosts 타인 쓰기 권한")
                details.append("  ✗ 취약: others write 권한 있음")
                result['status'] = 'VULNERABLE'
            else:
                details.append("  ✓ 양호")
        
        # 4. /etc/ssh/sshd_config 권한
        details.append("\n[파일권한-4] /etc/ssh/sshd_config 권한")
        
        stdin, stdout, stderr = ssh.exec_command("ls -l /etc/ssh/sshd_config")
        sshd_perm = stdout.read().decode().strip()
        
        if sshd_perm:
            details.append(f"  {sshd_perm}")
            
            # 600 권한 권장
            if not sshd_perm.startswith('-rw-------'):
                result['vulnerabilities'].append("sshd_config 권한 부적절")
                details.append("  ⚠ 주의: 600 권한 권장")
            else:
                details.append("  ✓ 양호: 600 권한")
        
        # 5. 홈 디렉터리 권한
        details.append("\n[파일권한-5] 홈 디렉터리 권한 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            """
            for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
                home=$(eval echo ~$user)
                if [ -d "$home" ]; then
                    ls -ld "$home" | awk '{print $1, $3, $9}'
                fi
            done | head -10
            """
        )
        home_perms = stdout.read().decode().strip()
        
        if home_perms:
            details.append("  사용자 홈 디렉터리:")
            for line in home_perms.split('\n')[:5]:
                perm, owner, path = line.split()
                details.append(f"    {perm} {owner} {path}")
                
                # 750 이하 (others 권한 없어야 함)
                if perm[7:10] != '---':
                    result['vulnerabilities'].append(f"홈 디렉터리 타인 권한: {path}")
                    details.append(f"      ✗ 취약: others 권한 제거 필요")
                    result['status'] = 'VULNERABLE'
        else:
            details.append("  • 일반 사용자 없음")
        
        # 6. World-Writable 파일 검색
        details.append("\n[파일권한-6] World-Writable 파일 검색")
        
        stdin, stdout, stderr = ssh.exec_command(
            "find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -20"
        )
        world_writable = stdout.read().decode().strip()
        
        if world_writable:
            ww_count = len(world_writable.split('\n'))
            result['vulnerabilities'].append(f"World-writable 파일: {ww_count}개")
            details.append(f"  ✗ 취약: {ww_count}개 발견")
            for line in world_writable.split('\n')[:5]:
                details.append(f"    {line}")
            if ww_count > 5:
                details.append(f"    ... 외 {ww_count - 5}개")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: world-writable 파일 없음")
        
        # 7. World-Writable 디렉터리 (sticky bit 확인)
        details.append("\n[파일권한-7] World-Writable 디렉터리 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "find / -xdev -type d -perm -0002 ! -perm -1000 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -10"
        )
        ww_dirs = stdout.read().decode().strip()
        
        if ww_dirs:
            result['vulnerabilities'].append("Sticky bit 없는 world-writable 디렉터리")
            details.append(f"  ✗ 취약: sticky bit 필요")
            for line in ww_dirs.split('\n')[:5]:
                details.append(f"    {line}")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: 적절한 디렉터리 권한")
        
        # 8. SetUID 파일 검색
        details.append("\n[파일권한-8] SetUID 파일 검색")
        
        stdin, stdout, stderr = ssh.exec_command(
            "find / -xdev -type f -perm -4000 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -20"
        )
        setuid_files = stdout.read().decode().strip()
        
        if setuid_files:
            setuid_count = len(setuid_files.split('\n'))
            details.append(f"  SetUID 파일: {setuid_count}개")
            
            # 알려진 필수 SetUID 파일 제외하고 검사
            essential_setuid = [
                '/usr/bin/sudo',
                '/usr/bin/passwd',
                '/usr/bin/su',
                '/bin/ping',
                '/bin/mount',
                '/bin/umount',
            ]
            
            suspicious_count = 0
            for line in setuid_files.split('\n')[:10]:
                is_essential = any(essential in line for essential in essential_setuid)
                if not is_essential:
                    if suspicious_count == 0:
                        details.append("  ⚠ 검토 필요:")
                    details.append(f"    {line}")
                    suspicious_count += 1
            
            if suspicious_count > 0:
                result['vulnerabilities'].append(f"불필요한 SetUID 파일 가능성: {suspicious_count}개")
                details.append(f"  ⚠ {suspicious_count}개 파일 검토 필요")
        else:
            details.append("  • SetUID 파일 없음")
        
        # 9. SetGID 파일 검색
        details.append("\n[파일권한-9] SetGID 파일 검색")
        
        stdin, stdout, stderr = ssh.exec_command(
            "find / -xdev -type f -perm -2000 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -20"
        )
        setgid_files = stdout.read().decode().strip()
        
        if setgid_files:
            setgid_count = len(setgid_files.split('\n'))
            details.append(f"  SetGID 파일: {setgid_count}개")
            for line in setgid_files.split('\n')[:5]:
                details.append(f"    {line}")
        else:
            details.append("  • SetGID 파일 없음")
        
        # 10. /tmp 디렉터리 권한
        details.append("\n[파일권한-10] /tmp 디렉터리 권한")
        
        stdin, stdout, stderr = ssh.exec_command("ls -ld /tmp")
        tmp_perm = stdout.read().decode().strip()
        
        if tmp_perm:
            details.append(f"  {tmp_perm}")
            
            # sticky bit (drwxrwxrwt)
            if not tmp_perm.startswith('drwxrwxrwt'):
                result['vulnerabilities'].append("/tmp 권한 부적절")
                details.append("  ✗ 취약: 1777 (sticky bit) 필요")
                result['status'] = 'VULNERABLE'
            else:
                details.append("  ✓ 양호: sticky bit 설정")
        
        # 11. 주요 시스템 디렉터리 소유권
        details.append("\n[파일권한-11] 시스템 디렉터리 소유권")
        
        system_dirs = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin']
        
        for sys_dir in system_dirs:
            stdin, stdout, stderr = ssh.exec_command(f"ls -ld {sys_dir}")
            dir_info = stdout.read().decode().strip()
            
            if dir_info:
                owner = dir_info.split()[2]
                if owner != 'root':
                    result['vulnerabilities'].append(f"{sys_dir} 소유자: {owner}")
                    details.append(f"  ✗ {sys_dir}: {owner} (root 필요)")
                    result['status'] = 'VULNERABLE'
        
        if result['status'] == 'SAFE':
            details.append("  ✓ 양호: 시스템 디렉터리 소유권 적절")
        
        # 12. 숨겨진 파일 권한
        details.append("\n[파일권한-12] 사용자 숨겨진 파일 권한")
        
        stdin, stdout, stderr = ssh.exec_command(
            """
            for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | head -3); do
                home=$(eval echo ~$user)
                if [ -d "$home" ]; then
                    find "$home" -name ".*" -type f 2>/dev/null | head -5
                fi
            done
            """
        )
        hidden_files = stdout.read().decode().strip()
        
        if hidden_files:
            details.append(f"  숨겨진 파일 확인 (샘플):")
            for line in hidden_files.split('\n')[:5]:
                details.append(f"    {line}")
            details.append("  • .bashrc, .bash_history 등 권한 확인 권장")
        
        ssh.close()
        
    except paramiko.AuthenticationException:
        details.append("  [ERROR] SSH 인증 실패")
        result['status'] = 'ERROR'
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result