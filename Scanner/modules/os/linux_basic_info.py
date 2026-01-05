"""
인프라 진단: Linux 시스템 기본 정보 수집
hostname, kernel version, OS release, uptime, resource usage
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ssh_utils import safe_ssh_connect, create_error_result
def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Linux 시스템 기본 정보',
        'category': '시스템 정보',
        'status': 'SAFE',
        'severity': 'INFO',
        'vulnerabilities': [],
        'recommendation': '자산 목록 최신화 및 관리',
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
        
        # 1. Hostname & Kernel
        stdin, stdout, stderr = ssh.exec_command("uname -a")
        kernel_info = stdout.read().decode().strip()
        details.append(f"[시스템] 커널 정보:\n  {kernel_info}")
        
        stdin, stdout, stderr = ssh.exec_command("hostname")
        hostname = stdout.read().decode().strip()
        details.append(f"\n[시스템] 호스트네임:\n  {hostname}")

        # 2. OS Release
        stdin, stdout, stderr = ssh.exec_command("cat /etc/os-release | grep PRETTY_NAME")
        os_release = stdout.read().decode().strip().replace('PRETTY_NAME=', '').replace('"', '')
        if not os_release:
            stdin, stdout, stderr = ssh.exec_command("cat /etc/issue.net")
            os_release = stdout.read().decode().strip()
        
        details.append(f"\n[시스템] OS 버전:\n  {os_release}")
        
        # 3. Uptime
        stdin, stdout, stderr = ssh.exec_command("uptime -p")
        uptime = stdout.read().decode().strip()
        details.append(f"\n[시스템] 가동 시간:\n  {uptime}")
        
        # 4. CPU/Memory (Load Average)
        stdin, stdout, stderr = ssh.exec_command("uptime")
        load_avg = stdout.read().decode().strip().split('load average:')[-1]
        details.append(f"\n[리소스] Load Average:\n {load_avg}")
        
        stdin, stdout, stderr = ssh.exec_command("free -h")
        memory_info = stdout.read().decode().strip()
        details.append(f"\n[리소스] 메모리 사용량:\n{memory_info}")
        
        # 5. Disk Usage
        stdin, stdout, stderr = ssh.exec_command("df -h / | grep -v Filesystem")
        disk_info = stdout.read().decode().strip()
        details.append(f"\n[리소스] 디스크 사용량 (/):\n  {disk_info}")

        ssh.close()
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
