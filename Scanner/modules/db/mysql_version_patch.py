"""
KISA DB 보안 가이드 - MySQL 버전 및 패치 점검
DB-13: 최신 버전 업데이트
DB-14: 보안 패치 적용
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from ssh_utils import safe_ssh_connect, create_error_result
import re

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'MySQL 버전 및 패치 점검',
        'category': 'KISA DB 보안 - 패치 관리',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'MySQL 최신 버전으로 업데이트, 보안 패치 정기 점검, EOL 버전 사용 금지',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, port=ssh_port, username=ssh_user, password=ssh_pass, key_filename=ssh_key_file)
        
        # MySQL 버전 확인
        cmd = "mysql -V"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        mysql_version_output = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if mysql_version_output:
            details.append(f"MySQL 버전 정보:\n{mysql_version_output}")
            
            # 버전 번호 추출
            version_match = re.search(r'(\d+\.\d+\.\d+)', mysql_version_output)
            if version_match:
                version = version_match.group(1)
                major_version = version.split('.')[0]
                minor_version = version.split('.')[1]
                
                details.append(f"\n버전: {version}")
                details.append(f"메이저 버전: {major_version}.{minor_version}")
                
                # EOL 버전 체크
                if int(major_version) < 5:
                    details.append("⚠️ MySQL 4.x는 EOL(End of Life) 버전입니다")
                    result['vulnerabilities'].append('지원 종료된 MySQL 버전 사용 중')
                    result['status'] = 'VULNERABLE'
                elif major_version == '5' and int(minor_version) < 7:
                    details.append("⚠️ MySQL 5.6 이하는 EOL 버전입니다")
                    result['vulnerabilities'].append('지원 종료된 MySQL 5.6 이하 버전 사용')
                    result['status'] = 'VULNERABLE'
                elif major_version == '5' and minor_version == '7':
                    details.append("⚠️ MySQL 5.7은 2023년 10월 지원 종료")
                    result['vulnerabilities'].append('MySQL 5.7 사용 중 (지원 종료)')
                    if result['status'] == 'SAFE':
                        result['status'] = 'WARN'
                elif major_version == '8':
                    details.append("✓ MySQL 8.x 사용 중 (지원 버전)")
                else:
                    details.append(f"MySQL {major_version}.{minor_version} 버전 확인 필요")
        
        # MySQL 서버 버전 (실행중인 버전)
        cmd = "mysql -u root -e \"SELECT VERSION();\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        server_version = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if server_version:
            details.append(f"\n실행 중인 MySQL 서버 버전:\n{server_version}")
        
        # 설치된 MySQL 패키지 확인 (CentOS/RHEL)
        cmd = "rpm -qa | grep -i mysql"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        rpm_packages = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if rpm_packages:
            details.append(f"\n설치된 MySQL 패키지:\n{rpm_packages}")
        else:
            # Debian/Ubuntu
            cmd = "dpkg -l | grep -i mysql"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            deb_packages = stdout.read().decode('utf-8', errors='ignore').strip()
            
            if deb_packages:
                details.append(f"\n설치된 MySQL 패키지:\n{deb_packages[:500]}")
        
        # 보안 업데이트 확인 (yum/apt)
        cmd = "yum check-update mysql* 2>/dev/null | grep mysql || apt list --upgradable 2>/dev/null | grep mysql"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        updates_available = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if updates_available and len(updates_available) > 10:
            details.append(f"\n⚠️ 사용 가능한 업데이트:\n{updates_available[:300]}")
            result['vulnerabilities'].append('MySQL 보안 업데이트가 사용 가능')
            if result['status'] == 'SAFE':
                result['status'] = 'WARN'
        else:
            details.append("\n✓ 사용 가능한 업데이트 없음")
        
        # 컴파일 옵션 확인
        cmd = "mysql -u root -e \"SHOW VARIABLES LIKE 'version_compile%';\""
        stdin, stdout, stderr = ssh.exec_command(cmd)
        compile_info = stdout.read().decode('utf-8', errors='ignore').strip()
        
        if compile_info:
            details.append(f"\n컴파일 정보:\n{compile_info}")
        
        ssh.close()
        
    except Exception as e:
        result['status'] = 'ERROR'
        result['details'] = f"오류: {str(e)}"
        return result
    
    result['details'] = '\n'.join(details)
    return result
