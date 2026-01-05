"""
서비스 탐지기

열린 포트의 서비스 배너를 분석하여 정확한 서비스 정보를 식별합니다.
"""
import socket
import re
from typing import Optional


class ServiceDetector:
    """서비스 배너 분석기"""
    
    # 서비스별 배너 패턴
    BANNER_PATTERNS = {
        'ssh': [
            (r'SSH-(\d+\.\d+)-OpenSSH[_-]?(\S+)?', 'OpenSSH'),
            (r'SSH-(\d+\.\d+)-dropbear', 'Dropbear'),
        ],
        'ftp': [
            (r'220.*vsftpd', 'vsftpd'),
            (r'220.*ProFTPD', 'ProFTPD'),
            (r'220.*FileZilla', 'FileZilla'),
            (r'220.*Pure-FTPd', 'Pure-FTPd'),
            (r'220.*Microsoft FTP', 'Microsoft FTP'),
        ],
        'smtp': [
            (r'220.*Postfix', 'Postfix'),
            (r'220.*Sendmail', 'Sendmail'),
            (r'220.*Microsoft ESMTP', 'Microsoft ESMTP'),
            (r'220.*Exim', 'Exim'),
        ],
        'mysql': [
            (r'mysql', 'MySQL'),
            (r'MariaDB', 'MariaDB'),
        ],
        'postgresql': [
            (r'PostgreSQL', 'PostgreSQL'),
        ],
        'redis': [
            (r'REDIS', 'Redis'),
            (r'\+PONG', 'Redis'),
        ],
        'mongodb': [
            (r'MongoDB', 'MongoDB'),
        ],
        'http': [
            (r'Server:\s*(nginx[\s/]?\S*)', 'Nginx'),
            (r'Server:\s*(Apache[\s/]?\S*)', 'Apache'),
            (r'Server:\s*(Microsoft-IIS[\s/]?\S*)', 'IIS'),
            (r'Server:\s*(LiteSpeed)', 'LiteSpeed'),
            (r'Server:\s*(Caddy)', 'Caddy'),
        ],
    }
    
    # 서비스별 프로브 데이터
    PROBES = {
        'http': b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n',
        'redis': b'PING\r\n',
        'mysql': b'',  # MySQL은 연결 시 자동 응답
        'smtp': b'',
        'ftp': b'',
        'ssh': b'',
    }
    
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
    
    def grab_banner(self, host: str, port: int, probe: bytes = b'') -> Optional[str]:
        """
        배너 그래빙
        
        Args:
            host: 대상 호스트
            port: 대상 포트
            probe: 전송할 프로브 데이터
            
        Returns:
            배너 문자열 또는 None
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((host, port))
            
            # 프로브 전송
            if probe:
                sock.send(probe)
            
            # 응답 수신
            banner = sock.recv(1024)
            return banner.decode('utf-8', errors='ignore').strip()
            
        except socket.error:
            return None
        finally:
            sock.close()
    
    def detect_service(self, host: str, port: int, 
                       hint_service: str = None) -> dict:
        """
        서비스 탐지
        
        Args:
            host: 대상 호스트
            port: 대상 포트
            hint_service: 예상 서비스 힌트 (포트 스캔 결과)
            
        Returns:
            {
                'port': int,
                'service': str,
                'product': str,
                'version': str,
                'banner': str,
                'extra_info': dict
            }
        """
        result = {
            'port': port,
            'service': hint_service or 'unknown',
            'product': None,
            'version': None,
            'banner': None,
            'extra_info': {},
        }
        
        # 프로브 선택
        probe = self.PROBES.get(hint_service, b'')
        
        # 배너 그래빙
        banner = self.grab_banner(host, port, probe)
        if banner:
            result['banner'] = banner[:200]  # 최대 200자
            
            # 패턴 매칭
            patterns = self.BANNER_PATTERNS.get(hint_service, [])
            for pattern, product in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    result['product'] = product
                    if match.groups():
                        result['version'] = match.group(1)
                    break
            
            # 추가 정보 추출
            result['extra_info'] = self._extract_extra_info(banner, hint_service)
        
        return result
    
    def _extract_extra_info(self, banner: str, service: str) -> dict:
        """배너에서 추가 정보 추출"""
        info = {}
        
        if service == 'ssh':
            # SSH 프로토콜 버전
            match = re.search(r'SSH-(\d+\.\d+)', banner)
            if match:
                info['protocol'] = match.group(1)
            
            # 운영체제 힌트
            if 'Ubuntu' in banner:
                info['os_hint'] = 'Ubuntu'
            elif 'Debian' in banner:
                info['os_hint'] = 'Debian'
        
        elif service == 'http':
            # 추가 헤더 추출
            if 'X-Powered-By' in banner:
                match = re.search(r'X-Powered-By:\s*(\S+)', banner)
                if match:
                    info['powered_by'] = match.group(1)
        
        return info
    
    def detect_from_port_scan(self, host: str, port_scan_result: dict) -> list:
        """
        포트 스캔 결과를 기반으로 서비스 탐지
        
        Args:
            host: 대상 호스트
            port_scan_result: PortScanner의 결과
            
        Returns:
            서비스 정보 리스트
        """
        services = []
        
        for port_info in port_scan_result.get('open_ports', []):
            port = port_info['port']
            hint_service = port_info.get('service')
            
            service_info = self.detect_service(host, port, hint_service)
            services.append(service_info)
        
        return services


def detect_services(host: str, ports: list) -> list:
    """
    단순화된 인터페이스: 지정된 포트의 서비스 탐지
    
    Args:
        host: 대상 호스트
        ports: 탐지할 포트 리스트
        
    Returns:
        서비스 정보 리스트
    """
    detector = ServiceDetector()
    results = []
    
    for port in ports:
        result = detector.detect_service(host, port)
        results.append(result)
    
    return results


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python service_detector.py <host> <port>")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    
    print(f"[*] 서비스 탐지: {host}:{port}\n")
    
    detector = ServiceDetector()
    result = detector.detect_service(host, port)
    
    print("=" * 50)
    print(f"포트: {result['port']}")
    print(f"서비스: {result['service']}")
    print(f"제품: {result['product'] or 'Unknown'}")
    print(f"버전: {result['version'] or 'Unknown'}")
    print("=" * 50)
    
    if result['banner']:
        print(f"\n배너:\n{result['banner'][:200]}")
