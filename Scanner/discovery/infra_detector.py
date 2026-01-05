#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
인프라 타입 자동 감지

포트 스캔 및 서비스 배너 분석을 통해 대상 서버의 인프라 유형을 식별합니다.
"""

from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
import socket
import re

try:
    from .port_scanner import PortScanner, COMMON_PORTS
    from .service_detector import ServiceDetector
except ImportError:
    from port_scanner import PortScanner, COMMON_PORTS
    from service_detector import ServiceDetector


class InfraDetector:
    """인프라 타입 자동 감지기"""
    
    # 서비스 → 모듈 매핑
    SERVICE_TO_MODULE = {
        # Web
        'http': 'web',
        'https': 'web',
        'http-alt': 'web',
        
        # Web Server
        'nginx': 'web_server',
        'apache': 'web_server',
        'iis': 'web_server',
        
        # WAS
        'tomcat': 'was',
        'jboss': 'was',
        'weblogic': 'was',
        'php-fpm': 'was',
        'ajp': 'was',
        
        # Database
        'mysql': 'db',
        'mariadb': 'db',
        'postgresql': 'db',
        'mongodb': 'db',
        'mssql': 'db',
        'oracle': 'db',
        'redis': 'db',
        'elasticsearch': 'db',
        
        # OS/Remote
        'ssh': 'os',
        
        # Cloud
        'aws': 'cloud',
        'gcp': 'cloud',
        'azure': 'cloud',
        
        # Network
        'dns': 'network',
        'ldap': 'network',
    }
    
    # 제품명 → 상세 타입
    PRODUCT_TYPES = {
        'nginx': 'nginx',
        'apache': 'apache',
        'iis': 'iis',
        'tomcat': 'tomcat',
        'mysql': 'mysql',
        'mariadb': 'mariadb',
        'postgresql': 'postgresql',
        'mongodb': 'mongodb',
        'redis': 'redis',
        'openssh': 'linux',
    }
    
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
        self.port_scanner = PortScanner(timeout=timeout)
        self.service_detector = ServiceDetector(timeout=timeout)
    
    def detect(self, target: str) -> Dict:
        """
        대상 서버의 인프라 유형 감지
        
        Args:
            target: URL 또는 IP 주소
            
        Returns:
            {
                'host': str,
                'services': list,          # 감지된 서비스 목록
                'web_servers': list,        # 웹 서버 목록 (nginx, apache 등)
                'databases': list,          # 데이터베이스 목록
                'was': list,                # WAS 목록
                'os_hint': str,             # 추정 OS
                'recommended_modules': list, # 추천 스캔 모듈
                'open_ports': list,         # 열린 포트 정보
            }
        """
        # URL에서 호스트 추출
        host = self._extract_host(target)
        
        result = {
            'host': host,
            'target': target,
            'services': [],
            'web_servers': [],
            'databases': [],
            'was': [],
            'os_hint': None,
            'recommended_modules': set(),
            'open_ports': [],
            'details': {},
        }
        
        # 1. 포트 스캔
        port_result = self.port_scanner.scan_common_ports(host)
        result['open_ports'] = port_result.get('open_ports', [])
        
        # 2. 서비스 상세 감지
        for port_info in result['open_ports']:
            port = port_info['port']
            service = port_info.get('service', 'unknown')
            
            # 배너 분석
            service_detail = self.service_detector.detect_service(
                host, port, hint_service=service
            )
            
            # 서비스 정보 수집
            self._process_service(result, port_info, service_detail)
        
        # 3. HTTP 헤더 분석 (웹 서비스가 있는 경우)
        if any(p['port'] in [80, 443, 8080, 8443] for p in result['open_ports']):
            self._detect_web_stack(result, host)
        
        # 4. 추천 모듈 결정
        result['recommended_modules'] = list(result['recommended_modules'])
        
        # 기본적으로 web 모듈은 HTTP가 있으면 포함
        if any(s in ['http', 'https'] for s in result['services']):
            if 'web' not in result['recommended_modules']:
                result['recommended_modules'].append('web')
        
        return result
    
    def _extract_host(self, target: str) -> str:
        """URL 또는 IP에서 호스트 추출"""
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.hostname or target
        return target.split(':')[0]
    
    def _process_service(self, result: Dict, port_info: Dict, 
                         service_detail: Dict) -> None:
        """서비스 정보 처리 및 분류"""
        service = port_info.get('service', 'unknown')
        product = service_detail.get('product')
        category = port_info.get('category', 'unknown')
        
        # 서비스 목록에 추가
        if service not in result['services']:
            result['services'].append(service)
        
        # 모듈 추천
        module = self.SERVICE_TO_MODULE.get(service)
        if module:
            result['recommended_modules'].add(module)
        
        # 카테고리별 분류
        if category == 'database' or service in ['mysql', 'postgresql', 'mongodb', 'redis']:
            db_name = product or service
            if db_name not in result['databases']:
                result['databases'].append(db_name)
            result['recommended_modules'].add('db')
        
        elif category == 'was' or service in ['ajp', 'php-fpm']:
            was_name = product or service
            if was_name not in result['was']:
                result['was'].append(was_name)
            result['recommended_modules'].add('was')
        
        # OS 힌트
        extra_info = service_detail.get('extra_info', {})
        if 'os_hint' in extra_info and not result['os_hint']:
            result['os_hint'] = extra_info['os_hint']
            result['recommended_modules'].add('os')
        
        # 상세 정보 저장
        result['details'][port_info['port']] = {
            'service': service,
            'product': product,
            'version': service_detail.get('version'),
            'banner': service_detail.get('banner'),
        }
    
    def _detect_web_stack(self, result: Dict, host: str) -> None:
        """HTTP 헤더 분석으로 웹 스택 감지"""
        import requests
        
        try:
            # HTTP 요청
            for scheme in ['https', 'http']:
                try:
                    resp = requests.get(
                        f"{scheme}://{host}",
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False
                    )
                    headers = resp.headers
                    break
                except:
                    continue
            else:
                return
            
            # Server 헤더
            server = headers.get('Server', '')
            if server:
                server_lower = server.lower()
                if 'nginx' in server_lower:
                    if 'nginx' not in result['web_servers']:
                        result['web_servers'].append('nginx')
                    result['recommended_modules'].add('web_server')
                elif 'apache' in server_lower:
                    if 'apache' not in result['web_servers']:
                        result['web_servers'].append('apache')
                    result['recommended_modules'].add('web_server')
                elif 'iis' in server_lower:
                    if 'iis' not in result['web_servers']:
                        result['web_servers'].append('iis')
                    result['recommended_modules'].add('web_server')
            
            # X-Powered-By
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                powered_lower = powered_by.lower()
                if 'php' in powered_lower:
                    if 'php' not in result['was']:
                        result['was'].append('php')
                    result['recommended_modules'].add('was')
                elif 'asp' in powered_lower:
                    if 'asp.net' not in result['was']:
                        result['was'].append('asp.net')
                    result['recommended_modules'].add('was')
                elif 'express' in powered_lower:
                    if 'express' not in result['was']:
                        result['was'].append('express')
                    result['recommended_modules'].add('was')
            
            # 특정 프레임워크 감지
            set_cookie = headers.get('Set-Cookie', '')
            if 'JSESSIONID' in set_cookie:
                if 'java' not in result['was']:
                    result['was'].append('java')
                result['recommended_modules'].add('was')
            elif 'PHPSESSID' in set_cookie:
                if 'php' not in result['was']:
                    result['was'].append('php')
                result['recommended_modules'].add('was')
            elif 'ASP.NET' in set_cookie:
                if 'asp.net' not in result['was']:
                    result['was'].append('asp.net')
                result['recommended_modules'].add('was')
                
        except Exception:
            pass
    
    def get_scan_recommendation(self, detection_result: Dict) -> Dict:
        """
        감지 결과를 기반으로 스캔 추천 생성
        
        Returns:
            {
                'modules': list,           # 실행할 모듈 목록
                'priority_order': list,    # 우선순위 순서
                'skip_modules': list,      # 건너뛸 모듈
                'estimated_scripts': int,  # 예상 스크립트 수
            }
        """
        all_modules = {'web', 'web_server', 'was', 'db', 'os', 'network', 'cloud', 'framework'}
        recommended = set(detection_result.get('recommended_modules', []))
        
        # HTTP가 있으면 web 기본 포함
        if detection_result.get('services'):
            if any(s in ['http', 'https'] for s in detection_result['services']):
                recommended.add('web')
        
        # 건너뛸 모듈
        skip = all_modules - recommended
        
        # 우선순위 (중요도 순)
        priority = []
        for mod in ['web', 'db', 'was', 'web_server', 'os', 'cloud', 'network', 'framework']:
            if mod in recommended:
                priority.append(mod)
        
        # 예상 스크립트 수 (대략적)
        script_counts = {
            'web': 54,
            'db': 6,
            'was': 4,
            'web_server': 2,
            'os': 7,
            'cloud': 2,
            'network': 2,
            'framework': 3,
        }
        estimated = sum(script_counts.get(m, 0) for m in recommended)
        
        return {
            'modules': list(recommended),
            'priority_order': priority,
            'skip_modules': list(skip),
            'estimated_scripts': estimated,
            'total_available': sum(script_counts.values()),
        }


def detect_infra(target: str, timeout: float = 2.0) -> Dict:
    """
    단순화된 인터페이스: 인프라 감지
    
    Args:
        target: URL 또는 IP 주소
        timeout: 타임아웃 (초)
        
    Returns:
        인프라 감지 결과
    """
    detector = InfraDetector(timeout=timeout)
    return detector.detect(target)


if __name__ == '__main__':
    import sys
    import warnings
    warnings.filterwarnings('ignore')
    
    if len(sys.argv) < 2:
        print("Usage: python infra_detector.py <target>")
        print("Example: python infra_detector.py https://example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"[*] 인프라 감지 시작: {target}\n")
    
    detector = InfraDetector()
    result = detector.detect(target)
    
    print("=" * 60)
    print(f"호스트: {result['host']}")
    print("=" * 60)
    
    print(f"\n[포트] 열린 포트: {len(result['open_ports'])}개")
    for p in result['open_ports']:
        print(f"  - {p['port']}/tcp: {p['service']}")
    
    print(f"\n[서비스] 감지된 서비스:")
    print(f"  - 서비스: {', '.join(result['services']) or 'None'}")
    print(f"  - 웹 서버: {', '.join(result['web_servers']) or 'None'}")
    print(f"  - 데이터베이스: {', '.join(result['databases']) or 'None'}")
    print(f"  - WAS: {', '.join(result['was']) or 'None'}")
    print(f"  - OS 힌트: {result['os_hint'] or 'Unknown'}")
    
    recommendation = detector.get_scan_recommendation(result)
    print(f"\n[추천] 스캔 모듈:")
    print(f"  - 실행: {', '.join(recommendation['modules'])}")
    print(f"  - 스킵: {', '.join(recommendation['skip_modules'])}")
    print(f"  - 예상 스크립트: {recommendation['estimated_scripts']}/{recommendation['total_available']}개")
