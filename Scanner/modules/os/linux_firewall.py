"""
KISA Linux 보안 가이드 - 방화벽 설정 점검
"""
import paramiko


def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Linux 방화벽 설정 점검',
        'category': 'KISA Linux 보안',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '방화벽 활성화 및 최소 포트 개방 원칙 적용',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, 
                    password=ssh_pass, key_filename=ssh_key_file, timeout=10)
        
        # 1. UFW 상태 확인
        details.append("[방화벽-1] UFW 상태 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "sudo ufw status 2>/dev/null || echo 'not_installed'"
        )
        ufw_status = stdout.read().decode().strip()
        
        if 'not_installed' in ufw_status or 'command not found' in ufw_status:
            details.append("  • UFW 미설치")
        elif 'inactive' in ufw_status.lower():
            result['vulnerabilities'].append("UFW 방화벽 비활성화")
            details.append("  ✗ UFW 비활성화")
            result['status'] = 'VULNERABLE'
        elif 'active' in ufw_status.lower():
            details.append("  ✓ UFW 활성화")
        
        # 2. iptables 상태 확인
        details.append("\n[방화벽-2] iptables 규칙 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "sudo iptables -L -n 2>/dev/null | head -30"
        )
        iptables_rules = stdout.read().decode().strip()
        
        if iptables_rules:
            rule_count = len([l for l in iptables_rules.split('\n') 
                              if l and not l.startswith('Chain') and not l.startswith('target')])
            details.append(f"  iptables 규칙 수: {rule_count}개")
            
            if 'ACCEPT' in iptables_rules and rule_count == 0:
                result['vulnerabilities'].append("iptables 기본 정책이 ACCEPT")
                details.append("  ✗ 기본 ACCEPT 정책 (위험)")
                result['status'] = 'VULNERABLE'
        else:
            details.append("  • iptables 미설정")
        
        # 3. firewalld 상태 확인
        details.append("\n[방화벽-3] firewalld 상태 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "sudo systemctl is-active firewalld 2>/dev/null"
        )
        firewalld_status = stdout.read().decode().strip()
        
        if firewalld_status == 'active':
            details.append("  ✓ firewalld 활성화")
            
            # 열린 서비스 확인
            stdin, stdout, stderr = ssh.exec_command(
                "sudo firewall-cmd --list-all 2>/dev/null | grep 'services:'"
            )
            services = stdout.read().decode().strip()
            if services:
                details.append(f"  {services}")
        else:
            details.append("  • firewalld 미실행")
        
        # 4. 개방된 포트 확인
        details.append("\n[방화벽-4] 외부 개방 포트")
        
        stdin, stdout, stderr = ssh.exec_command(
            "sudo ss -tuln | grep LISTEN | awk '{print $5}' | grep -E '0\\.0\\.0\\.0:|\\*:|::' | head -15"
        )
        open_external = stdout.read().decode().strip()
        
        if open_external:
            ports = open_external.split('\n')
            details.append(f"  외부 개방 포트: {len(ports)}개")
            for port in ports[:10]:
                details.append(f"    {port}")
            
            # 위험 포트 체크
            dangerous = ['23', '21', '3389', '1433', '3306', '27017']
            for d in dangerous:
                if f':{d}' in open_external:
                    result['vulnerabilities'].append(f"위험 포트 외부 개방: {d}")
                    result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 외부 개방 포트 없음")
        
        # 5. 방화벽 없음 감지
        details.append("\n[방화벽-5] 방화벽 활성화 여부")
        
        stdin, stdout, stderr = ssh.exec_command(
            "sudo systemctl is-active ufw firewalld iptables 2>/dev/null | grep -c active"
        )
        active_fw = stdout.read().decode().strip()
        
        if active_fw == '0' or not active_fw:
            result['vulnerabilities'].append("활성화된 방화벽 없음")
            details.append("  ✗ 어떤 방화벽도 활성화되지 않음")
            result['status'] = 'VULNERABLE'
            result['severity'] = 'CRITICAL'
        else:
            details.append(f"  ✓ {active_fw}개 방화벽 활성화")
        
        ssh.close()
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
