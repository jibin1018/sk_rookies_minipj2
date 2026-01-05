"""
인프라 진단: Linux 프로세스 감사
실행 중인 프로세스 점검, 리소스 과점유 및 의심스러운 프로세스 식별
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ssh_utils import safe_ssh_connect, create_error_result
def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Linux 실행 프로세스 감사',
        'category': '시스템 관리',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '불필요하거나 의심스러운 프로세스 종료 및 원인 분석',
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
        
        # 1. 리소스 상위 점유 프로세스 확인 (CPU/MEM)
        cmd = "ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -10"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        top_processes = stdout.read().decode().strip()
        
        details.append("[프로세스] 리소스 Top 10 프로세스:")
        details.append(top_processes)
        
        # 2. 의심스러운 프로세스 패턴 확인
        suspicious_list = ['nc', 'netcat', 'nmap', 'hydra', 'john', 'xmrig', 'minerd']
        found_suspicious = []
        
        cmd = "ps -eo pid,cmd"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        all_procs = stdout.read().decode().strip()
        
        for line in all_procs.split('\n')[1:]:
            for susp in suspicious_list:
                if f" {susp} " in line or line.endswith(f" {susp}"):
                    found_suspicious.append(line.strip())
        
        if found_suspicious:
            result['vulnerabilities'].append(f"의심스러운 프로세스 발견: {len(found_suspicious)}개")
            details.append("\n[⚠] 의심스러운 프로세스 발견:")
            for p in found_suspicious:
                details.append(f"  - {p}")
            result['status'] = 'VULNERABLE'
            result['severity'] = 'HIGH'
        else:
            details.append("\n[✓] 알려진 의심 프로세스(백도어, 채굴 등) 미발견")
            
        ssh.close()
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
