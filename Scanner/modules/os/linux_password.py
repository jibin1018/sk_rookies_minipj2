"""
KISA Linux 보안 가이드 - U-02: 패스워드 정책
패스워드 최소 길이, 복잡도, 유효기간, 재사용 제한
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22):
    result = {
        'name': 'U-02: Linux 패스워드 정책',
        'category': 'KISA Linux 보안',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '패스워드 최소 8자, 복잡도 설정, 최대 90일, 최소 1일, 재사용 제한',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, timeout=10)
        
        # 1. 패스워드 최소 길이 확인
        details.append("[패스워드-1] 패스워드 최소 길이 확인")
        
        # login.defs 확인
        stdin, stdout, stderr = ssh.exec_command(
            "grep '^PASS_MIN_LEN' /etc/login.defs"
        )
        min_len = stdout.read().decode().strip()
        
        if min_len:
            length = int(min_len.split()[-1])
            details.append(f"  PASS_MIN_LEN: {length}")
            
            if length < 8:
                result['vulnerabilities'].append(f"패스워드 최소 길이 부족: {length}자")
                details.append(f"  ✗ 취약: {length}자 (8자 이상 권장)")
                result['status'] = 'VULNERABLE'
            else:
                details.append(f"  ✓ 양호: {length}자")
        else:
            result['vulnerabilities'].append("PASS_MIN_LEN 미설정")
            details.append("  ✗ 취약: 최소 길이 설정 없음")
            result['status'] = 'VULNERABLE'
        
        # 2. 패스워드 최대 사용 기간
        details.append("\n[패스워드-2] 패스워드 최대 사용 기간")
        
        stdin, stdout, stderr = ssh.exec_command(
            "grep '^PASS_MAX_DAYS' /etc/login.defs"
        )
        max_days = stdout.read().decode().strip()
        
        if max_days:
            days = int(max_days.split()[-1])
            details.append(f"  PASS_MAX_DAYS: {days}")
            
            if days > 90 or days == 99999:
                result['vulnerabilities'].append(f"패스워드 유효기간 과다: {days}일")
                details.append(f"  ✗ 취약: {days}일 (90일 이하 권장)")
                result['status'] = 'VULNERABLE'
            else:
                details.append(f"  ✓ 양호: {days}일")
        else:
            result['vulnerabilities'].append("PASS_MAX_DAYS 미설정")
            details.append("  ✗ 취약: 최대 사용 기간 없음")
            result['status'] = 'VULNERABLE'
        
        # 3. 패스워드 최소 사용 기간
        details.append("\n[패스워드-3] 패스워드 최소 사용 기간")
        
        stdin, stdout, stderr = ssh.exec_command(
            "grep '^PASS_MIN_DAYS' /etc/login.defs"
        )
        min_days = stdout.read().decode().strip()
        
        if min_days:
            days = int(min_days.split()[-1])
            details.append(f"  PASS_MIN_DAYS: {days}")
            
            if days < 1:
                result['vulnerabilities'].append("패스워드 최소 사용 기간 없음")
                details.append(f"  ⚠ 주의: {days}일 (1일 이상 권장)")
            else:
                details.append(f"  ✓ 양호: {days}일")
        else:
            details.append("  ⚠ PASS_MIN_DAYS 미설정")
        
        # 4. 패스워드 만료 경고 기간
        details.append("\n[패스워드-4] 패스워드 만료 경고")
        
        stdin, stdout, stderr = ssh.exec_command(
            "grep '^PASS_WARN_AGE' /etc/login.defs"
        )
        warn_age = stdout.read().decode().strip()
        
        if warn_age:
            days = int(warn_age.split()[-1])
            details.append(f"  PASS_WARN_AGE: {days}일 전 경고")
            
            if days < 7:
                details.append(f"  ⚠ 주의: {days}일 (7일 이상 권장)")
            else:
                details.append(f"  ✓ 양호: {days}일")
        else:
            details.append("  • PASS_WARN_AGE 미설정")
        
        # 5. PAM 패스워드 복잡도 설정 (pam_pwquality 또는 pam_cracklib)
        details.append("\n[패스워드-5] 패스워드 복잡도 설정 (PAM)")
        
        # Ubuntu/Debian 계열
        stdin, stdout, stderr = ssh.exec_command(
            "grep 'pam_pwquality.so\\|pam_cracklib.so' /etc/pam.d/common-password 2>/dev/null"
        )
        pam_complexity = stdout.read().decode().strip()
        
        # CentOS/RHEL 계열
        if not pam_complexity:
            stdin, stdout, stderr = ssh.exec_command(
                "grep 'pam_pwquality.so\\|pam_cracklib.so' /etc/pam.d/system-auth 2>/dev/null"
            )
            pam_complexity = stdout.read().decode().strip()
        
        if pam_complexity:
            details.append(f"  ✓ PAM 복잡도 모듈 활성화:")
            
            # 상세 설정 확인
            if 'minlen=' in pam_complexity:
                import re
                minlen = re.search(r'minlen=(\d+)', pam_complexity)
                if minlen:
                    details.append(f"    minlen={minlen.group(1)}")
            
            complexity_options = ['dcredit', 'ucredit', 'lcredit', 'ocredit']
            for opt in complexity_options:
                if opt in pam_complexity:
                    match = re.search(rf'{opt}=(-?\d+)', pam_complexity)
                    if match:
                        details.append(f"    {opt}={match.group(1)}")
            
            # 복잡도 설정이 약한지 확인
            if 'minlen=' not in pam_complexity:
                result['vulnerabilities'].append("PAM 최소 길이 미설정")
                details.append("  ⚠ minlen 설정 없음")
        else:
            result['vulnerabilities'].append("PAM 복잡도 모듈 미사용")
            details.append("  ✗ 취약: pam_pwquality/pam_cracklib 미설정")
            result['status'] = 'VULNERABLE'
        
        # 6. pwquality.conf 설정 확인
        details.append("\n[패스워드-6] pwquality.conf 상세 설정")
        
        stdin, stdout, stderr = ssh.exec_command(
            "cat /etc/security/pwquality.conf 2>/dev/null | grep -v '^#' | grep -v '^$'"
        )
        pwquality_conf = stdout.read().decode().strip()
        
        if pwquality_conf:
            details.append("  pwquality.conf 설정:")
            for line in pwquality_conf.split('\n')[:10]:
                details.append(f"    {line}")
            
            # 주요 설정 체크
            required_settings = {
                'minlen': 8,
                'dcredit': -1,  # 숫자 1개 이상
                'ucredit': -1,  # 대문자 1개 이상
                'lcredit': -1,  # 소문자 1개 이상
                'ocredit': -1,  # 특수문자 1개 이상
            }
            
            for setting, min_val in required_settings.items():
                if setting not in pwquality_conf:
                    details.append(f"  ⚠ {setting} 미설정")
        else:
            details.append("  • pwquality.conf 파일 없음")
        
        # 7. 패스워드 재사용 제한
        details.append("\n[패스워드-7] 패스워드 재사용 제한")
        
        # Ubuntu/Debian
        stdin, stdout, stderr = ssh.exec_command(
            "grep 'pam_pwhistory.so\\|remember=' /etc/pam.d/common-password 2>/dev/null"
        )
        remember = stdout.read().decode().strip()
        
        # CentOS/RHEL
        if not remember:
            stdin, stdout, stderr = ssh.exec_command(
                "grep 'pam_pwhistory.so\\|remember=' /etc/pam.d/system-auth 2>/dev/null"
            )
            remember = stdout.read().decode().strip()
        
        if remember:
            details.append(f"  ✓ 패스워드 재사용 제한:")
            details.append(f"    {remember}")
            
            # remember 값 추출
            import re
            remember_val = re.search(r'remember=(\d+)', remember)
            if remember_val:
                count = int(remember_val.group(1))
                if count < 4:
                    details.append(f"  ⚠ remember={count} (4개 이상 권장)")
                else:
                    details.append(f"  ✓ remember={count}")
        else:
            result['vulnerabilities'].append("패스워드 재사용 제한 없음")
            details.append("  ✗ 취약: remember 설정 없음")
            result['status'] = 'VULNERABLE'
        
        # 8. 계정 잠금 정책 (로그인 실패 시)
        details.append("\n[패스워드-8] 계정 잠금 정책 (faillock/pam_tally2)")
        
        # faillock (최신)
        stdin, stdout, stderr = ssh.exec_command(
            "grep 'pam_faillock.so' /etc/pam.d/common-auth /etc/pam.d/system-auth 2>/dev/null"
        )
        faillock = stdout.read().decode().strip()
        
        # pam_tally2 (구형)
        stdin, stdout, stderr = ssh.exec_command(
            "grep 'pam_tally2.so' /etc/pam.d/common-auth /etc/pam.d/system-auth 2>/dev/null"
        )
        tally2 = stdout.read().decode().strip()
        
        if faillock:
            details.append("  ✓ faillock 설정:")
            
            # deny, unlock_time 확인
            import re
            deny = re.search(r'deny=(\d+)', faillock)
            unlock_time = re.search(r'unlock_time=(\d+)', faillock)
            
            if deny:
                details.append(f"    deny={deny.group(1)}")
            if unlock_time:
                details.append(f"    unlock_time={unlock_time.group(1)}")
                
        elif tally2:
            details.append("  ✓ pam_tally2 설정:")
            details.append(f"    {tally2}")
        else:
            result['vulnerabilities'].append("계정 잠금 정책 없음")
            details.append("  ✗ 취약: faillock/pam_tally2 미설정")
            result['status'] = 'VULNERABLE'
        
        # 9. 실제 사용자 패스워드 정책 적용 확인
        details.append("\n[패스워드-9] 사용자별 패스워드 정책 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "sudo chage -l $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | head -1) 2>/dev/null"
        )
        user_policy = stdout.read().decode().strip()
        
        if user_policy:
            details.append("  샘플 사용자 정책:")
            for line in user_policy.split('\n')[:5]:
                details.append(f"    {line}")
        else:
            details.append("  • 사용자 정책 확인 불가")
        
        # 10. root 패스워드 변경 이력
        details.append("\n[패스워드-10] root 패스워드 변경 이력")
        
        stdin, stdout, stderr = ssh.exec_command(
            "sudo chage -l root 2>/dev/null | grep 'Last password change'"
        )
        root_pass_change = stdout.read().decode().strip()
        
        if root_pass_change:
            details.append(f"  {root_pass_change}")
            
            # 90일 이상 변경 안 했는지 체크 (간단 버전)
            if 'never' in root_pass_change.lower():
                result['vulnerabilities'].append("root 패스워드 변경 이력 없음")
                details.append("  ⚠ root 패스워드 변경 필요")
        else:
            details.append("  • root 패스워드 변경 이력 확인 불가")
        
        ssh.close()
        
    except paramiko.AuthenticationException:
        details.append("  [ERROR] SSH 인증 실패")
        result['status'] = 'ERROR'
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result