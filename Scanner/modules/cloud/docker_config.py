"""
Docker 보안 설정 점검 (SSH 기반)
"""
import paramiko


def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'Docker 보안 설정 점검',
        'category': 'Container Security',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'Docker 데몬 보안 설정 강화, 루트리스 모드 검토',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user,
                    password=ssh_pass, key_filename=ssh_key_file, timeout=10)
        
        # 1. Docker 설치 확인
        details.append("[Docker-1] Docker 설치 확인")
        
        stdin, stdout, stderr = ssh.exec_command("docker --version 2>/dev/null")
        docker_version = stdout.read().decode().strip()
        
        if not docker_version:
            details.append("  • Docker 미설치")
            result['details'] = '\n'.join(details)
            ssh.close()
            return result
        
        details.append(f"  {docker_version}")
        
        # 2. Docker 데몬 소켓 권한
        details.append("\n[Docker-2] Docker 소켓 권한")
        
        stdin, stdout, stderr = ssh.exec_command("ls -la /var/run/docker.sock 2>/dev/null")
        socket_perms = stdout.read().decode().strip()
        
        if socket_perms:
            details.append(f"  {socket_perms}")
            if 'rw-rw----' not in socket_perms and 'srw-rw----' not in socket_perms:
                if 'rw-rw-rw-' in socket_perms:
                    result['vulnerabilities'].append("Docker 소켓 전역 쓰기 권한")
                    result['status'] = 'VULNERABLE'
                    details.append("  ✗ 전역 쓰기 권한 (위험)")
        
        # 3. Docker 데몬 TCP 노출
        details.append("\n[Docker-3] Docker TCP 포트 노출")
        
        stdin, stdout, stderr = ssh.exec_command(
            "sudo netstat -tuln 2>/dev/null | grep -E ':2375|:2376' || "
            "sudo ss -tuln 2>/dev/null | grep -E ':2375|:2376'"
        )
        docker_tcp = stdout.read().decode().strip()
        
        if docker_tcp:
            if ':2375' in docker_tcp:
                result['vulnerabilities'].append("Docker 2375 포트 노출 (비암호화)")
                result['status'] = 'VULNERABLE'
                result['severity'] = 'CRITICAL'
                details.append("  ✗ 포트 2375 노출 (비암호화, 매우 위험)")
            if ':2376' in docker_tcp:
                details.append("  ⚠ 포트 2376 노출 (TLS)")
        else:
            details.append("  ✓ TCP 포트 미노출 (Unix 소켓만 사용)")
        
        # 4. 실행 중인 컨테이너 확인
        details.append("\n[Docker-4] 실행 중인 컨테이너")
        
        stdin, stdout, stderr = ssh.exec_command(
            "docker ps --format '{{.Names}}: {{.Image}}' 2>/dev/null | head -10"
        )
        containers = stdout.read().decode().strip()
        
        if containers:
            count = len(containers.split('\n'))
            details.append(f"  실행 중: {count}개")
            for line in containers.split('\n')[:5]:
                details.append(f"    {line}")
        else:
            details.append("  • 실행 중인 컨테이너 없음")
        
        # 5. Privileged 컨테이너 확인
        details.append("\n[Docker-5] Privileged 컨테이너 확인")
        
        stdin, stdout, stderr = ssh.exec_command(
            "docker ps -q 2>/dev/null | xargs -I {} docker inspect {} 2>/dev/null | "
            "grep -A1 '\"Privileged\"' | grep true"
        )
        privileged = stdout.read().decode().strip()
        
        if privileged:
            result['vulnerabilities'].append("Privileged 모드 컨테이너 실행 중")
            result['status'] = 'VULNERABLE'
            details.append("  ✗ Privileged 컨테이너 발견 (호스트 전체 접근 가능)")
        else:
            details.append("  ✓ Privileged 컨테이너 없음")
        
        # 6. Root로 실행되는 컨테이너
        details.append("\n[Docker-6] Root 실행 컨테이너")
        
        stdin, stdout, stderr = ssh.exec_command(
            "docker ps -q 2>/dev/null | xargs -I {} docker exec {} whoami 2>/dev/null | grep -c root"
        )
        root_count = stdout.read().decode().strip()
        
        if root_count and int(root_count) > 0:
            details.append(f"  ⚠ Root로 실행 중인 컨테이너: {root_count}개")
        else:
            details.append("  ✓ Root 실행 컨테이너 없음 또는 확인 불가")
        
        # 7. Docker 네트워크
        details.append("\n[Docker-7] Docker 네트워크")
        
        stdin, stdout, stderr = ssh.exec_command(
            "docker network ls --format '{{.Name}}: {{.Driver}}' 2>/dev/null"
        )
        networks = stdout.read().decode().strip()
        
        if networks:
            for line in networks.split('\n')[:5]:
                details.append(f"  {line}")
        
        # 8. 이미지 취약점 스캔 도구
        details.append("\n[Docker-8] 이미지 스캔 도구")
        
        stdin, stdout, stderr = ssh.exec_command("which trivy 2>/dev/null")
        trivy = stdout.read().decode().strip()
        
        if trivy:
            details.append("  ✓ Trivy 설치됨")
        else:
            details.append("  ⚠ Trivy 미설치 (이미지 취약점 스캔 권장)")
        
        ssh.close()
        
    except Exception as e:
        details.append(f"  [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = '\n'.join(details)
    return result
