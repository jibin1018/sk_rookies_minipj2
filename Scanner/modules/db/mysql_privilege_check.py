"""
KISA DB 보안 가이드 - MySQL 권한 및 역할 점검
DB-15: 과도한 권한 제거
DB-16: GRANT OPTION 제한
"""

import paramiko

def scan(ssh_host, ssh_user, ssh_pass, ssh_port=22, ssh_key_file=None):
    result = {
        'name': 'MySQL 권한 및 역할 점검',
        'category': 'KISA DB 보안 - 권한 관리',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': 'ALL PRIVILEGES 제거, GRANT OPTION 제한, FILE 권한 제한, SUPER 권한 최소화',
        'details': ''
    }
    
    details = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing
