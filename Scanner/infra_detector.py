"""
인프라 탐지 모듈

HTTP 응답을 분석하여 대상 시스템의 인프라 타입을 식별합니다.
- 웹 서버 (Nginx, Apache, IIS)
- 프로그래밍 언어 (PHP, Java, Python, Node.js)
- 프레임워크 (Spring, Django, Laravel)
- 데이터베이스 (MySQL, PostgreSQL, MongoDB)
- WAS (Tomcat, WildFly)
"""

import re
import socket
import requests
from urllib.parse import urlparse

from infra_mapping import DETECTION_PATTERNS


class InfraDetector:
    """인프라 타입 탐지기"""
    
    # 일반적인 데이터베이스 포트
    DB_PORTS = {
        3306: 'mysql',
        5432: 'postgresql',
        27017: 'mongodb',
        1433: 'mssql',
        1521: 'oracle',
        6379: 'redis',
    }
    
    def __init__(self, timeout: int = 5):
        """
        Args:
            timeout: HTTP 요청 및 포트 스캔 타임아웃 (초)
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
        })
    
    def detect(self, target_url: str) -> dict:
        """
        대상 URL의 인프라 타입을 탐지합니다.
        
        Args:
            target_url: 분석할 URL
            
        Returns:
            인프라 프로필 딕셔너리:
            {
                'web_server': str | None,
                'language': str | None,
                'framework': str | None,
                'database': str | None,
                'was': str | None,
                'os': str | None,
                'raw_headers': dict,
                'detection_methods': list
            }
        """
        profile = {
            'web_server': None,
            'language': None,
            'framework': None,
            'database': None,
            'was': None,
            'os': None,
            'raw_headers': {},
            'detection_methods': [],
        }
        
        try:
            # HTTP 요청으로 헤더 수집
            response = self._fetch_headers(target_url)
            if response:
                profile['raw_headers'] = dict(response.headers)
                
                # 헤더 기반 탐지
                self._detect_from_headers(response.headers, profile)
                
                # 쿠키 기반 탐지
                self._detect_from_cookies(response.cookies, profile)
                
                # 응답 본문 기반 탐지 (에러 페이지 등)
                self._detect_from_body(response.text, profile)
            
            # 포트 스캔으로 DB 탐지 (선택적)
            parsed = urlparse(target_url)
            if parsed.hostname:
                self._detect_database_port(parsed.hostname, profile)
            
            # OS 추론
            self._infer_os(profile)
            
        except Exception as e:
            profile['error'] = str(e)
        
        return profile
    
    def _fetch_headers(self, url: str) -> requests.Response | None:
        """HTTP 요청을 보내 응답을 수집합니다."""
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            return response
        except requests.RequestException:
            return None
    
    def _detect_from_headers(self, headers: dict, profile: dict):
        """HTTP 헤더를 분석하여 인프라를 탐지합니다."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Server 헤더 분석
        server = headers_lower.get('server', '')
        if server:
            profile['detection_methods'].append(f'Server header: {server}')
            
            # 웹 서버 탐지
            for ws_type, patterns in DETECTION_PATTERNS['web_server'].items():
                if any(p in server for p in patterns):
                    profile['web_server'] = ws_type
                    break
            
            # WAS 탐지 (Server 헤더에서)
            for was_type, patterns in DETECTION_PATTERNS['was'].items():
                if any(p in server for p in patterns):
                    profile['was'] = was_type
                    break
        
        # X-Powered-By 헤더 분석
        powered_by = headers_lower.get('x-powered-by', '')
        if powered_by:
            profile['detection_methods'].append(f'X-Powered-By: {powered_by}')
            
            # 언어 탐지
            for lang, patterns in DETECTION_PATTERNS['language'].items():
                if any(p in powered_by for p in patterns):
                    profile['language'] = lang
                    break
            
            # 프레임워크 탐지
            for fw, patterns in DETECTION_PATTERNS['framework'].items():
                if any(p in powered_by for p in patterns):
                    profile['framework'] = fw
                    break
        
        # X-AspNet-Version 헤더
        if 'x-aspnet-version' in headers_lower:
            profile['language'] = 'asp'
            profile['detection_methods'].append('X-AspNet-Version header')
        
        # X-Application-Context (Spring)
        if 'x-application-context' in headers_lower:
            profile['framework'] = 'spring'
            profile['language'] = 'java'
            profile['detection_methods'].append('X-Application-Context header')
    
    def _detect_from_cookies(self, cookies: requests.cookies.RequestsCookieJar, profile: dict):
        """쿠키 이름을 분석하여 프레임워크를 탐지합니다."""
        cookie_names = [c.name.lower() for c in cookies]
        
        # 프레임워크별 쿠키 패턴
        cookie_patterns = {
            'django': ['csrftoken', 'sessionid'],
            'laravel': ['laravel_session', 'xsrf-token'],
            'rails': ['_session_id', '_rails'],
            'spring': ['jsessionid'],
        }
        
        for fw, patterns in cookie_patterns.items():
            if any(p in cookie_names for p in patterns):
                if not profile['framework']:
                    profile['framework'] = fw
                    profile['detection_methods'].append(f'Cookie pattern: {fw}')
                
                # 프레임워크로 언어 추론
                if fw == 'django':
                    profile['language'] = 'python'
                elif fw == 'laravel':
                    profile['language'] = 'php'
                elif fw == 'rails':
                    profile['language'] = 'ruby'
                elif fw == 'spring':
                    profile['language'] = 'java'
                break
        
        # JSESSIONID → Java + Tomcat 추론
        if 'jsessionid' in cookie_names:
            profile['language'] = 'java'
            if not profile['was']:
                profile['was'] = 'tomcat'
            profile['detection_methods'].append('JSESSIONID cookie detected')
    
    def _detect_from_body(self, body: str, profile: dict):
        """응답 본문을 분석하여 인프라를 탐지합니다."""
        body_lower = body.lower()
        
        # 에러 페이지 패턴
        error_patterns = {
            'apache': ['apache/', 'apache server'],
            'nginx': ['nginx/', 'nginx server'],
            'iis': ['iis/', 'microsoft-iis'],
            'tomcat': ['apache tomcat', 'tomcat/'],
        }
        
        for infra, patterns in error_patterns.items():
            if any(p in body_lower for p in patterns):
                if infra in ['apache', 'nginx', 'iis']:
                    if not profile['web_server']:
                        profile['web_server'] = infra
                        profile['detection_methods'].append(f'Error page: {infra}')
                elif infra == 'tomcat':
                    if not profile['was']:
                        profile['was'] = 'tomcat'
                        profile['detection_methods'].append('Error page: tomcat')
                break
        
        # 프레임워크 시그니처
        framework_sigs = {
            'django': ['csrfmiddlewaretoken', 'django debug'],
            'laravel': ['laravel', 'illuminate'],
            'spring': ['whitelabel error page', 'spring'],
            'rails': ['actioncontroller', 'rails'],
        }
        
        for fw, sigs in framework_sigs.items():
            if any(sig in body_lower for sig in sigs):
                if not profile['framework']:
                    profile['framework'] = fw
                    profile['detection_methods'].append(f'Body signature: {fw}')
                break
    
    def _detect_database_port(self, hostname: str, profile: dict):
        """포트 스캔으로 데이터베이스를 탐지합니다."""
        for port, db_type in self.DB_PORTS.items():
            if self._is_port_open(hostname, port):
                profile['database'] = db_type
                profile['detection_methods'].append(f'Port {port} open: {db_type}')
                break
    
    def _is_port_open(self, hostname: str, port: int) -> bool:
        """특정 포트가 열려있는지 확인합니다."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((hostname, port))
            return result == 0
        except socket.error:
            return False
        finally:
            sock.close()
    
    def _infer_os(self, profile: dict):
        """탐지된 정보로 OS를 추론합니다."""
        # IIS → Windows
        if profile['web_server'] == 'iis':
            profile['os'] = 'windows'
            profile['detection_methods'].append('OS inferred from IIS')
            return
        
        # ASP.NET → Windows
        if profile['language'] == 'asp':
            profile['os'] = 'windows'
            profile['detection_methods'].append('OS inferred from ASP.NET')
            return
        
        # 그 외 → Linux (기본값)
        if profile['web_server'] in ['nginx', 'apache']:
            profile['os'] = 'linux'
            profile['detection_methods'].append('OS inferred (default: linux)')


def detect_infrastructure(target_url: str) -> dict:
    """
    단순화된 인터페이스: URL을 받아 인프라 프로필을 반환합니다.
    
    Args:
        target_url: 분석할 URL
        
    Returns:
        인프라 프로필 딕셔너리
    """
    detector = InfraDetector()
    return detector.detect(target_url)


if __name__ == '__main__':
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python infra_detector.py <URL>")
        sys.exit(1)
    
    url = sys.argv[1]
    print(f"[*] 인프라 탐지 중: {url}\n")
    
    result = detect_infrastructure(url)
    
    print("=" * 50)
    print("📋 인프라 프로필")
    print("=" * 50)
    print(f"  웹 서버:    {result.get('web_server') or 'Unknown'}")
    print(f"  언어:       {result.get('language') or 'Unknown'}")
    print(f"  프레임워크: {result.get('framework') or 'Unknown'}")
    print(f"  데이터베이스: {result.get('database') or 'Unknown'}")
    print(f"  WAS:        {result.get('was') or 'Unknown'}")
    print(f"  OS:         {result.get('os') or 'Unknown'}")
    print("=" * 50)
    print("\n탐지 방법:")
    for method in result.get('detection_methods', []):
        print(f"  - {method}")
