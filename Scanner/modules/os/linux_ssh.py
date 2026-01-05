"""
KISA Linux 보안 가이드 - SSH 보안 설정 점검
"""
import paramiko


def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Linux SSH 보안 설정 점검',
        'category': 'KISA Linux 보안',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'SSH 보안 설정 강화: root 로그인 비활성화, 키 인증 사용',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user,
                    password=ssh_pass, key_filename=ssh_key_file, timeout=10)
        
        # SSH 설정 파일 읽기
        stdin, stdout, stderr = ssh.exec_command(
            "sudo cat /etc/ssh/sshd_config 2>/dev/null"
        )
        sshd_config = stdout.read().decode()
        
        # 1. Root 로그인 허용 여부
        details.append("[SSH-1] Root 로그인 설정")
        
        if 'PermitRootLogin yes' in sshd_config:
            result['vulnerabilities'].append("Root 직접 로그인 허용됨")
            details.append("  ✗ PermitRootLogin yes (취약)")
            result['status'] = 'VULNERABLE'
        elif 'PermitRootLogin no' in sshd_config or 'PermitRootLogin prohibit-password' in sshd_config:
            details.append("  ✓ Root 로그인 비활성화")
        else:
            details.append("  ⚠ PermitRootLogin 미설정 (기본값 사용)")
        
        # 2. 패스워드 인증 여부
        details.append("\n[SSH-2] 패스워드 인증 설정")
        
        if 'PasswordAuthentication yes' in sshd_config:
            result['vulnerabilities'].append("패스워드 인증 허용 (키 인증 권장)")
            details.append("  ⚠ PasswordAuthentication yes")
        elif 'PasswordAuthentication no' in sshd_config:
            details.append("  ✓ 패스워드 인증 비활성화 (키 인증만)")
        else:
            details.append("  • PasswordAuthentication 미설정")
        
        # 3. 빈 패스워드 허용 여부
        details.append("\n[SSH-3] 빈 패스워드 허용 설정")
        
        if 'PermitEmptyPasswords yes' in sshd_config:
            result['vulnerabilities'].append("빈 패스워드 허용됨")
            details.append("  ✗ PermitEmptyPasswords yes (매우 취약)")
            result['status'] = 'VULNERABLE'
            result['severity'] = 'CRITICAL'
        else:
            details.append("  ✓ 빈 패스워드 비허용")
        
        # 4. SSH 프로토콜 버전
        details.append("\n[SSH-4] SSH 프로토콜 버전")
        
        if 'Protocol 1' in sshd_config:
            result['vulnerabilities'].append("SSH Protocol 1 사용 (취약)")
            details.append("  ✗ Protocol 1 (취약, 2 권장)")
            result['status'] = 'VULNERABLE'
        elif 'Protocol 2' in sshd_config:
            details.append("  ✓ Protocol 2 사용")
        else:
            details.append("  ✓ 기본 Protocol 2 (최신 버전)")
        
        # 5. MaxAuthTries 설정
        details.append("\n[SSH-5] 최대 인증 시도 횟수")
        
        import re
        max_auth_match = re.search(r'MaxAuthTries\s+(\d+)', sshd_config)
        if max_auth_match:
            max_tries = int(max_auth_match.group(1))
            if max_tries > 5:
                result['vulnerabilities'].append(f"MaxAuthTries {max_tries} (5 이하 권장)")
                details.append(f"  ⚠ MaxAuthTries {max_tries} (너무 높음)")
            else:
                details.append(f"  ✓ MaxAuthTries {max_tries}")
        else:
            details.append("  • MaxAuthTries 미설정 (기본값 6)")
        
        # 6. LoginGraceTime 설정
        details.append("\n[SSH-6] 로그인 유예 시간")
        
        grace_match = re.search(r'LoginGraceTime\s+(\d+)', sshd_config)
        if grace_match:
            grace_time = int(grace_match.group(1))
            if grace_time > 60:
                details.append(f"  ⚠ LoginGraceTime {grace_time}초 (60초 이하 권장)")
            else:
                details.append(f"  ✓ LoginGraceTime {grace_time}초")
        else:
            details.append("  • LoginGraceTime 미설정")
        
        # 7. SSH 포트 확인
        details.append("\n[SSH-7] SSH 포트 설정")
        
        port_match = re.search(r'^Port\s+(\d+)', sshd_config, re.MULTILINE)
        if port_match:
            ssh_port_cfg = int(port_match.group(1))
            if ssh_port_cfg == 22:
                details.append("  ⚠ 기본 포트 22 사용 (변경 권장)")
            else:
                details.append(f"  ✓ 포트 {ssh_port_cfg} 사용 (기본 22 변경)")
        else:
            details.append("  ⚠ 기본 포트 22 사용")
        
        # 8. X11 Forwarding
        details.append("\n[SSH-8] X11 Forwarding 설정")
        
        if 'X11Forwarding yes' in sshd_config:
            details.append("  ⚠ X11Forwarding 활성화 (필요시만 사용)")
        else:
            details.append("  ✓ X11Forwarding 비활성화")
        
        # 9. AllowUsers/AllowGroups 설정
        details.append("\n[SSH-9] 접근 제한 설정")
        
        if 'AllowUsers' in sshd_config or 'AllowGroups' in sshd_config:
            details.append("  ✓ AllowUsers/AllowGroups 설정됨")
        else:
            details.append("  ⚠ 접근 제한 미설정 (AllowUsers 권장)")
        
        # 10. 최근 SSH 접속 실패 로그
        details.append("\n[SSH-10] 최근 SSH 접속 실패")
        
        stdin, stdout, stderr = ssh.exec_command(
            "sudo grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -5 || "
            "sudo grep 'Failed password' /var/log/secure 2>/dev/null | tail -5"
        )
        failed_logs = stdout.read().decode().strip()
        
        if failed_logs:
            fail_count = len(failed_logs.split('\n'))
            details.append(f"  ⚠ 최근 접속 실패 기록 {fail_count}건")
        else:
            details.append("  ✓ 최근 접속 실패 없음")
        
        ssh.close()
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
