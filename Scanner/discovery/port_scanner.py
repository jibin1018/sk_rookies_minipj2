"""
포트 스캐너

TCP 포트를 스캔하여 열린 서비스를 탐지합니다.
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


# 주요 서비스 포트 정의
COMMON_PORTS = {
    # 웹 서비스
    80: {'service': 'http', 'category': 'web'},
    443: {'service': 'https', 'category': 'web'},
    8080: {'service': 'http-alt', 'category': 'was'},
    8443: {'service': 'https-alt', 'category': 'was'},
    
    # SSH/원격
    22: {'service': 'ssh', 'category': 'remote'},
    3389: {'service': 'rdp', 'category': 'remote'},
    
    # 파일 전송
    21: {'service': 'ftp', 'category': 'file'},
    69: {'service': 'tftp', 'category': 'file'},
    
    # 데이터베이스
    3306: {'service': 'mysql', 'category': 'database'},
    5432: {'service': 'postgresql', 'category': 'database'},
    27017: {'service': 'mongodb', 'category': 'database'},
    1433: {'service': 'mssql', 'category': 'database'},
    1521: {'service': 'oracle', 'category': 'database'},
    6379: {'service': 'redis', 'category': 'database'},
    9200: {'service': 'elasticsearch', 'category': 'database'},
    
    # WAS
    8009: {'service': 'ajp', 'category': 'was'},
    9000: {'service': 'php-fpm', 'category': 'was'},
    9090: {'service': 'prometheus', 'category': 'monitoring'},
    
    # 메시지 큐
    5672: {'service': 'rabbitmq', 'category': 'mq'},
    9092: {'service': 'kafka', 'category': 'mq'},
    
    # 기타
    25: {'service': 'smtp', 'category': 'mail'},
    53: {'service': 'dns', 'category': 'network'},
    389: {'service': 'ldap', 'category': 'auth'},
    636: {'service': 'ldaps', 'category': 'auth'},
}


class PortScanner:
    """TCP 포트 스캐너"""
    
    def __init__(self, timeout: float = 1.0, max_workers: int = 50):
        """
        Args:
            timeout: 포트 연결 타임아웃 (초)
            max_workers: 동시 스캔 스레드 수
        """
        self.timeout = timeout
        self.max_workers = max_workers
    
    def scan_port(self, host: str, port: int) -> Optional[dict]:
        """
        단일 포트 스캔
        
        Returns:
            열린 경우 포트 정보 dict, 닫힌 경우 None
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                port_info = COMMON_PORTS.get(port, {
                    'service': 'unknown',
                    'category': 'unknown'
                })
                return {
                    'port': port,
                    'state': 'open',
                    'service': port_info['service'],
                    'category': port_info['category'],
                }
            return None
        except socket.error:
            return None
        finally:
            sock.close()
    
    def scan_common_ports(self, host: str) -> dict:
        """
        주요 포트 스캔
        
        Returns:
            {
                'host': str,
                'open_ports': list,
                'services': dict,  # category별 서비스 그룹
                'total_open': int
            }
        """
        open_ports = []
        services = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self.scan_port, host, port): port 
                for port in COMMON_PORTS.keys()
            }
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
                    
                    # 카테고리별 그룹화
                    category = result['category']
                    if category not in services:
                        services[category] = []
                    services[category].append(result['service'])
        
        # 포트 번호순 정렬
        open_ports.sort(key=lambda x: x['port'])
        
        return {
            'host': host,
            'open_ports': open_ports,
            'services': services,
            'total_open': len(open_ports),
        }
    
    def scan_range(self, host: str, start_port: int, end_port: int) -> dict:
        """
        포트 범위 스캔
        
        Args:
            host: 대상 호스트
            start_port: 시작 포트
            end_port: 종료 포트
        """
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self.scan_port, host, port): port
                for port in range(start_port, end_port + 1)
            }
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        open_ports.sort(key=lambda x: x['port'])
        
        return {
            'host': host,
            'range': f'{start_port}-{end_port}',
            'open_ports': open_ports,
            'total_open': len(open_ports),
        }


def scan_host(host: str, timeout: float = 1.0) -> dict:
    """
    단순화된 인터페이스: 호스트의 주요 포트 스캔
    
    Args:
        host: 대상 호스트
        timeout: 타임아웃 (초)
        
    Returns:
        포트 스캔 결과
    """
    scanner = PortScanner(timeout=timeout)
    return scanner.scan_common_ports(host)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python port_scanner.py <host>")
        sys.exit(1)
    
    host = sys.argv[1]
    print(f"[*] 포트 스캔 시작: {host}\n")
    
    result = scan_host(host)
    
    print("=" * 50)
    print(f"호스트: {result['host']}")
    print(f"열린 포트: {result['total_open']}개")
    print("=" * 50)
    
    for port_info in result['open_ports']:
        print(f"  {port_info['port']:5d}/tcp  {port_info['state']:6s}  {port_info['service']}")
    
    print("\n카테고리별 서비스:")
    for category, services in result['services'].items():
        print(f"  [{category}] {', '.join(services)}")
