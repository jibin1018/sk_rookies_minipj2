"""
인프라 진단: Linux 오픈 포트 및 서비스 확인
netstat/ss 명령어를 사용하여 리스닝 중인 포트와 서비스 식별
"""
import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Linux 오픈 포트 점검',
        'category': '네트워크 보안',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '불필요한 포트 비활성화 및 방화벽 정책 적용',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file, timeout=10)
        
        # 1. ss 명령어로 TCP 리스닝 포트 확인 (netstat은 없을 수 있음)
        # -t: tcp, -u: udp, -l: listening, -n: numeric, -p: process
        cmd = "sudo ss -tulnp 2>/dev/null"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        ports_output = stdout.read().decode().strip()
        
        # ss 실패 시 netstat 시도
        if not ports_output:
            cmd = "sudo netstat -tulnp 2>/dev/null"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            ports_output = stdout.read().decode().strip()
            
        if ports_output:
            lines = ports_output.split('\n')
            # 헤더 제외하고 내용 분석
            listening_ports = []
            dangerous_ports = {
                '21': 'FTP', '23': 'Telnet', '3389': 'RDP', 
                '445': 'SMB', '139': 'NetBIOS'
            }
            
            details.append("[네트워크] 리스닝 포트 목록:")
            details.append("-" * 60)
            details.append(f"{'Protocol':<10} {'Local Address':<25} {'Process':<20}")
            details.append("-" * 60)
            
            for line in lines[1:]: # 헤더 건너뜀
                parts = line.split()
                if len(parts) >= 5:
                    proto = parts[0]
                    local_addr = parts[3 if 'Local' not in line else 4] # ss/netstat 포맷 차이 고려해야 함, 단순화
                    
                    # ss output: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
                    # netstat output: Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name
                    
                    # 간단한 파싱 (정확도 보단 정보 제공)
                    if 'LISTEN' in line or 'UNCONN' in line:
                        details.append(line[:100]) # 너무 길면 자름
                        
                        # 위험 포트 탐지
                        for d_port, d_name in dangerous_ports.items():
                            if f":{d_port}" in line or f" {d_port} " in line:
                                result['vulnerabilities'].append(f"위험 포트 개방: {d_port} ({d_name})")
                                details.append(f"  ⚠ 경고: {d_name} 포트({d_port})가 개방되어 있습니다.")
                                result['status'] = 'VULNERABLE'
                                
            if not result['vulnerabilities']:
                details.append("\n✓ 특이 사항 없음 (위험 포트 미발견)")
                
        else:
            details.append("포트 정보를 가져올 수 없습니다 (권한 부족 또는 명령어 부재).")
            
        ssh.close()
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
