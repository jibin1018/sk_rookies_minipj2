"""
KISA Linux 보안 가이드 - U-01: 계정 관리
root 계정 원격 접속 제한, 불필요한 계정 제거, 패스워드 없는 계정 점검
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'U-01: Linux 계정 관리',
        'category': 'KISA Linux 보안',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'root 원격 접속 차단, 불필요한 계정 제거, 모든 계정 패스워드 설정',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file, timeout=10)
        
        # 1. root 원격 접속 제한 확인
        details.append("[계정-1] root 원격 접속 제한 확인")
        
        stdin, stdout, stderr = ssh.exec_command("grep -i '^PermitRootLogin' /etc/ssh/sshd_config")
        permit_root = stdout.read().decode().strip()
        
        if permit_root:
            if 'no' in permit_root.lower():
                details.append(f"  ✓ 양호: {permit_root}")
            else:
                result['vulnerabilities'].append("root 원격 접속 허용")
                details.append(f"  ✗ 취약: {permit_root}")
                result['status'] = 'VULNERABLE'
        else:
            result['vulnerabilities'].append("PermitRootLogin 미설정 (기본값: 허용)")
            details.append("  ✗ 취약: PermitRootLogin 설정 없음")
            result['status'] = 'VULNERABLE'
        
        # 2. 일반 사용자 계정 확인
        details.append("\n[계정-2] 일반 사용자 계정 확인")
        
        # UID 1000 이상인 사용자 (일반 사용자)
        stdin, stdout, stderr = ssh.exec_command(
            "awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3, $7}' /etc/passwd"
        )
        general_users = stdout.read().decode().strip()
        
        if general_users:
            user_count = len(general_users.split('\n'))
            details.append(f"  일반 사용자: {user_count}명")
            for user_line in general_users.split('\n')[:5]:
                details.append(f"    {user_line}")
            if user_count > 5:
                details.append(f"    ... 외 {user_count - 5}명")
        else:
            details.append("  일반 사용자 없음")
        
        # 3. 시스템 계정 확인 (UID < 1000)
        details.append("\n[계정-3] 시스템 계정 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "awk -F: '$3 < 1000 && $3 != 0 {print $1, $3, $7}' /etc/passwd | head -20"
        )
        system_users = stdout.read().decode().strip()
        
        if system_users:
            details.append(f"  시스템 계정: {len(system_users.split(chr(10)))}개")
            for line in system_users.split('\n')[:5]:
                details.append(f"    {line}")
        
        # 4. 불필요한 계정 확인
        details.append("\n[계정-4] 불필요한 계정 존재 확인")
        
        # 제거 권장 계정 목록
        unnecessary_accounts = [
            'lp', 'uucp', 'nuucp', 'ftp', 'anonymous',
            'games', 'news', 'gopher', 'operator'
        ]
        
        stdin, stdout, stderr = ssh.exec_command("cut -d: -f1 /etc/passwd")
        all_users = stdout.read().decode().strip().split('\n')
        
        found_unnecessary = [acc for acc in unnecessary_accounts if acc in all_users]
        
        if found_unnecessary:
            result['vulnerabilities'].append(f"불필요한 계정 존재: {', '.join(found_unnecessary)}")
            details.append(f"  ✗ 취약: {', '.join(found_unnecessary)}")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: 불필요한 계정 없음")
        
        # 5. 패스워드 없는 계정 확인
        details.append("\n[계정-5] 패스워드 없는 계정 확인")
        
        # shadow 파일에서 패스워드 필드가 비어있거나 '!' 또는 '*'만 있는 계정
        stdin, stdout, stderr = ssh.exec_command(
            "sudo awk -F: '($2 == \"\" || $2 == \"!\" || $2 == \"*\") && $1 != \"root\" {print $1, $2}' /etc/shadow 2>/dev/null"
        )
        no_password = stdout.read().decode().strip()
        
        if no_password:
            # 시스템 계정 제외하고 일반 계정만 체크
            stdin, stdout, stderr = ssh.exec_command(
                "sudo awk -F: '($2 == \"\" || $2 == \"!\" || $2 == \"*\") && $3 >= 1000 && $3 < 65534 {print $1}' /etc/shadow 2>/dev/null"
            )
            general_no_pass = stdout.read().decode().strip()
            
            if general_no_pass:
                result['vulnerabilities'].append("패스워드 없는 일반 계정 존재")
                details.append(f"  ✗ 취약: {general_no_pass.replace(chr(10), ', ')}")
                result['status'] = 'VULNERABLE'
            else:
                details.append("  ✓ 양호: 일반 계정 모두 패스워드 설정됨")
        else:
            details.append("  ✓ 양호: 모든 계정 패스워드 설정됨")
        
        # 6. 잠긴 계정 확인
        details.append("\n[계정-6] 잠긴 계정 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "sudo passwd -S -a 2>/dev/null | grep ' L ' | head -10"
        )
        locked_accounts = stdout.read().decode().strip()
        
        if locked_accounts:
            locked_count = len(locked_accounts.split('\n'))
            details.append(f"  잠긴 계정: {locked_count}개")
            for line in locked_accounts.split('\n')[:3]:
                details.append(f"    {line.split()[0]}")
        else:
            details.append("  • 잠긴 계정 확인 불가")
        
        # 7. UID 0인 계정 확인 (root 외)
        details.append("\n[계정-7] UID 0인 계정 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "awk -F: '$3 == 0 {print $1}' /etc/passwd"
        )
        uid_zero = stdout.read().decode().strip().split('\n')
        
        if len(uid_zero) > 1 or (len(uid_zero) == 1 and uid_zero[0] != 'root'):
            non_root_uid0 = [u for u in uid_zero if u != 'root']
            if non_root_uid0:
                result['vulnerabilities'].append(f"root 외 UID 0 계정: {', '.join(non_root_uid0)}")
                details.append(f"  ✗ 취약: {', '.join(non_root_uid0)}")
                result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: root만 UID 0")
        
        # 8. 중복 UID 확인
        details.append("\n[계정-8] 중복 UID 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "cut -d: -f3 /etc/passwd | sort | uniq -d"
        )
        duplicate_uid = stdout.read().decode().strip()
        
        if duplicate_uid:
            result['vulnerabilities'].append("중복 UID 존재")
            details.append(f"  ✗ 취약: UID {duplicate_uid}")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: 중복 UID 없음")
        
        # 9. 중복 사용자명 확인
        details.append("\n[계정-9] 중복 사용자명 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "cut -d: -f1 /etc/passwd | sort | uniq -d"
        )
        duplicate_user = stdout.read().decode().strip()
        
        if duplicate_user:
            result['vulnerabilities'].append("중복 사용자명 존재")
            details.append(f"  ✗ 취약: {duplicate_user}")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: 중복 사용자명 없음")
        
        # 10. 홈 디렉터리 소유권 확인
        details.append("\n[계정-10] 홈 디렉터리 소유권")
        
        stdin, stdout, stderr = ssh.exec_command(
            """
            for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
                home=$(eval echo ~$user)
                if [ -d "$home" ]; then
                    owner=$(stat -c %U "$home" 2>/dev/null)
                    if [ "$owner" != "$user" ]; then
                        echo "$user:$home:$owner"
                    fi
                fi
            done
            """
        )
        wrong_owner = stdout.read().decode().strip()
        
        if wrong_owner:
            result['vulnerabilities'].append("잘못된 홈 디렉터리 소유권")
            details.append(f"  ✗ 취약:")
            for line in wrong_owner.split('\n')[:3]:
                details.append(f"    {line}")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: 홈 디렉터리 소유권 적절")
        
        # 11. 마지막 로그인 시간 확인 (90일 이상 미접속)
        details.append("\n[계정-11] 장기 미사용 계정 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "lastlog -b 90 | tail -n +2 | grep -v 'Never logged in' | head -10"
        )
        old_login = stdout.read().decode().strip()
        
        if old_login:
            details.append(f"  ⚠ 주의: 90일 이상 미접속 계정 존재")
            for line in old_login.split('\n')[:3]:
                details.append(f"    {line.split()[0]}")
        else:
            details.append("  ✓ 양호: 장기 미사용 계정 없음")
        
        # 12. sudo 권한 계정 확인
        details.append("\n[계정-12] sudo 권한 계정 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "grep -E '^%sudo|^%wheel' /etc/group"
        )
        sudo_group = stdout.read().decode().strip()
        
        if sudo_group:
            for line in sudo_group.split('\n'):
                group_name = line.split(':')[0]
                members = line.split(':')[-1]
                if members:
                    details.append(f"  {group_name} 그룹: {members}")
                else:
                    details.append(f"  {group_name} 그룹: 멤버 없음")
        
        # sudoers 파일 확인
        stdin, stdout, stderr = ssh.exec_command(
            "sudo cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' | grep 'ALL=(ALL)' | head -5"
        )
        sudoers_all = stdout.read().decode().strip()
        
        if sudoers_all:
            details.append("  sudoers ALL=(ALL) 권한:")
            for line in sudoers_all.split('\n')[:3]:
                details.append(f"    {line.strip()}")
        
        ssh.close()
        
    except paramiko.AuthenticationException:
        details.append("  [ERROR] SSH 인증 실패")
        result['status'] = 'ERROR'
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result