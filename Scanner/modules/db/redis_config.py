import paramiko
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def check_redis_security(host, port, username, password):
    """
    Redis 보안 설정 점검 (KISA DB 보안 가이드 기반)
    """
    result = {
        'host': host,
        'port': port,
        'scan_time': datetime.now().isoformat(),
        'vulnerabilities': [],
        'status': 'SAFE'
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password, timeout=10)
        
        # 1. Redis 프로세스 확인
        stdin, stdout, stderr = ssh.exec_command("ps aux | grep redis")
        process_info = stdout.read().decode()
        
        if 'redis-server' in process_info:
            details.append("✓ Redis 서버 실행 중")
            
            # 2. Redis 설정 파일 확인
            stdin, stdout, stderr = ssh.exec_command("cat /etc/redis/redis.conf 2>/dev/null || cat /etc/redis.conf 2>/dev/null")
            config_content = stdout.read().decode()
            
            # 3. 패스워드 설정 확인
            if 'requirepass' not in config_content or config_content.find('# requirepass') != -1:
                details.append("✗ [취약] 패스워드 미설정")
                result['vulnerabilities'].append({
                    'category': '접근통제',
                    'item': 'Redis 패스워드 설정',
                    'severity': 'HIGH',
                    'description': 'requirepass가 설정되지 않음',
                    'recommendation': '/etc/redis/redis.conf에서 requirepass 설정 필요'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 패스워드 설정됨")
            
            # 4. bind 주소 확인
            if 'bind 0.0.0.0' in config_content or 'bind ::1' in config_content:
                details.append("✗ [취약] 모든 IP에서 접근 가능")
                result['vulnerabilities'].append({
                    'category': '접근통제',
                    'item': 'Redis 바인드 주소 설정',
                    'severity': 'HIGH',
                    'description': '모든 IP에서 Redis 접근 가능',
                    'recommendation': 'bind 127.0.0.1 또는 특정 IP만 허용하도록 설정'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ 안전한 bind 주소 설정")
            
            # 5. protected-mode 확인
            if 'protected-mode no' in config_content:
                details.append("✗ [취약] Protected mode 비활성화")
                result['vulnerabilities'].append({
                    'category': '접근통제',
                    'item': 'Redis Protected Mode',
                    'severity': 'MEDIUM',
                    'description': 'protected-mode가 비활성화됨',
                    'recommendation': 'protected-mode yes 설정 권장'
                })
                result['status'] = 'VULNERABLE'
            else:
                details.append("✓ Protected mode 활성화")
            
            # 6. 위험한 명령어 비활성화 확인
            dangerous_commands = ['FLUSHDB', 'FLUSHALL', 'KEYS', 'CONFIG', 'SHUTDOWN']
            disabled_commands = []
            
            for cmd in dangerous_commands:
                if f'rename-command {cmd}' in config_content:
                    disabled_commands.append(cmd)
            
            if len(disabled_commands) < 3:
                details.append(f"⚠ 위험 명령어 비활성화 부족 (비활성화: {len(disabled_commands)}/5)")
                result['vulnerabilities'].append({
                    'category': '권한관리',
                    'item': 'Redis 위험 명령어 비활성화',
                    'severity': 'MEDIUM',
                    'description': '위험한 명령어가 비활성화되지 않음',
                    'recommendation': 'FLUSHDB, FLUSHALL, CONFIG 등 위험 명령어를 rename-command로 비활성화 권장'
                })
            else:
                details.append(f"✓ 위험 명령어 {len(disabled_commands)}개 비활성화")
            
            # 7. maxmemory 정책 확인
            if 'maxmemory-policy' not in config_content:
                details.append("⚠ maxmemory 정책 미설정")
            else:
                details.append("✓ maxmemory 정책 설정됨")
            
            # 8. AOF 또는 RDB 백업 설정 확인
            if 'appendonly yes' in config_content or 'save ' in config_content:
                details.append("✓ 백업 설정 활성화")
            else:
                details.append("⚠ 백업 설정 확인 필요")
                result['vulnerabilities'].append({
                    'category': '백업관리',
                    'item': 'Redis 백업 설정',
                    'severity': 'LOW',
                    'description': 'AOF/RDB 백업이 비활성화됨',
                    'recommendation': 'appendonly yes 또는 save 설정 권장'
                })
            
            # 9. Redis 버전 확인
            stdin, stdout, stderr = ssh.exec_command("redis-server --version 2>/dev/null || redis-cli --version")
            version_info = stdout.read().decode()
            
            if version_info:
                details.append(f"✓ 설치 버전: {version_info.strip()}")
            else:
                details.append("⚠ 버전 정보 확인 불가")
            
        else:
            details.append("✗ Redis 서버가 실행되고 있지 않음")
        
        ssh.close()
        
    except paramiko.AuthenticationException:
        details.append("✗ [ERROR] SSH 인증 실패")
        result['status'] = 'ERROR'
    except Exception as e:
        details.append(f"✗ [ERROR] {str(e)}")
        result['status'] = 'ERROR'
    
    result['details'] = details
    return result
