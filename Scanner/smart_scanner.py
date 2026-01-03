#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SmartScanner - 인프라 기반 스마트 스캐너

인프라 타입을 자동 감지하고 관련 스크립트만 선별하여 실행합니다.
"""

import os
import sys
import importlib
import importlib.util
from typing import Dict, List, Optional, Callable
from pathlib import Path
from datetime import datetime

# 경로 설정
SCANNER_ROOT = Path(__file__).parent
sys.path.insert(0, str(SCANNER_ROOT))

from discovery import InfraDetector, detect_infra
from utils.script_registry import ScriptRegistry, CATEGORY_REQUIREMENTS


class SmartScanner:
    """인프라 기반 스마트 스캐너"""
    
    def __init__(self, timeout: float = 3.0, verbose: bool = True):
        """
        Args:
            timeout: 네트워크 타임아웃 (초)
            verbose: 상세 출력 여부
        """
        self.timeout = timeout
        self.verbose = verbose
        self.infra_detector = InfraDetector(timeout=timeout)
        self.script_registry = ScriptRegistry()
        
        # 결과 저장
        self.last_detection = None
        self.last_scan_result = None
    
    def log(self, message: str, level: str = "INFO"):
        """로그 출력"""
        if self.verbose:
            prefix = {
                "INFO": "[*]",
                "SUCCESS": "[✓]",
                "WARNING": "[!]",
                "ERROR": "[✗]",
            }.get(level, "[*]")
            print(f"{prefix} {message}")
    
    def detect_infrastructure(self, target: str) -> Dict:
        """
        인프라 타입 감지
        
        Args:
            target: URL 또는 IP 주소
            
        Returns:
            인프라 감지 결과
        """
        self.log(f"인프라 감지 시작: {target}")
        
        detection = self.infra_detector.detect(target)
        self.last_detection = detection
        
        # 결과 출력
        if self.verbose:
            self.log(f"열린 포트: {len(detection['open_ports'])}개", "SUCCESS")
            
            if detection['web_servers']:
                self.log(f"웹 서버: {', '.join(detection['web_servers'])}", "SUCCESS")
            if detection['databases']:
                self.log(f"데이터베이스: {', '.join(detection['databases'])}", "SUCCESS")
            if detection['was']:
                self.log(f"WAS: {', '.join(detection['was'])}", "SUCCESS")
            if detection['os_hint']:
                self.log(f"OS: {detection['os_hint']}", "SUCCESS")
        
        return detection
    
    def get_recommended_scripts(self, detection: Dict = None) -> Dict[str, List]:
        """
        추천 스크립트 목록 반환
        
        Args:
            detection: 인프라 감지 결과 (없으면 마지막 감지 결과 사용)
            
        Returns:
            카테고리별 스크립트 목록
        """
        if detection is None:
            detection = self.last_detection
        
        if detection is None:
            self.log("인프라 감지가 필요합니다", "ERROR")
            return {}
        
        # 감지된 서비스 및 제품 수집
        services = detection.get('services', [])
        products = (
            detection.get('web_servers', []) +
            detection.get('databases', []) +
            detection.get('was', [])
        )
        
        # 스크립트 필터링
        scripts = self.script_registry.filter_by_services(services, products)
        
        return scripts
    
    def scan(self, target: str, 
             modules: List[str] = None,
             skip_detection: bool = False) -> Dict:
        """
        스마트 스캔 실행
        
        Args:
            target: 스캔 대상 URL 또는 IP
            modules: 강제 지정할 모듈 목록 (None이면 자동 감지)
            skip_detection: 인프라 감지 건너뛰기
            
        Returns:
            {
                'target': str,
                'detection': dict,          # 인프라 감지 결과
                'executed_modules': list,   # 실행된 모듈
                'skipped_modules': list,    # 스킵된 모듈
                'results': list,            # 스캔 결과
                'summary': dict,            # 요약 통계
                'scan_time': float,         # 스캔 소요 시간
            }
        """
        start_time = datetime.now()
        
        result = {
            'target': target,
            'detection': None,
            'executed_modules': [],
            'skipped_modules': [],
            'results': [],
            'summary': {
                'total': 0,
                'safe': 0,
                'vulnerable': 0,
                'error': 0,
            },
            'scan_time': 0,
        }
        
        # 1. 인프라 감지
        if not skip_detection:
            detection = self.detect_infrastructure(target)
            result['detection'] = detection
            
            # 추천 모듈 결정
            if modules is None:
                recommendation = self.infra_detector.get_scan_recommendation(detection)
                modules = recommendation['modules']
                result['skipped_modules'] = recommendation['skip_modules']
                
                self.log(
                    f"선별된 모듈: {', '.join(modules)} "
                    f"({recommendation['estimated_scripts']}/{recommendation['total_available']}개)",
                    "SUCCESS"
                )
        
        # 2. 스크립트 필터링
        if modules:
            scripts_to_run = self.script_registry.filter_by_modules(modules)
        else:
            scripts_to_run = self.script_registry.discover_scripts()
        
        result['executed_modules'] = list(scripts_to_run.keys())
        
        # 3. 스크립트 실행
        self.log(f"\n스캔 시작: {len(result['executed_modules'])}개 모듈")
        
        for category, scripts in scripts_to_run.items():
            self.log(f"  [{category}] {len(scripts)}개 스크립트 실행 중...")
            
            for script_info in scripts:
                script_result = self._run_script(target, script_info)
                if script_result:
                    result['results'].append(script_result)
                    
                    # 통계 업데이트
                    result['summary']['total'] += 1
                    status = script_result.get('status', 'ERROR')
                    if status == 'SAFE':
                        result['summary']['safe'] += 1
                    elif status == 'VULNERABLE':
                        result['summary']['vulnerable'] += 1
                    else:
                        result['summary']['error'] += 1
        
        # 4. 완료
        end_time = datetime.now()
        result['scan_time'] = (end_time - start_time).total_seconds()
        
        self.last_scan_result = result
        
        # 요약 출력
        self.log(f"\n스캔 완료 ({result['scan_time']:.2f}초)", "SUCCESS")
        self.log(f"  - 전체: {result['summary']['total']}개")
        self.log(f"  - 안전: {result['summary']['safe']}개")
        self.log(f"  - 취약: {result['summary']['vulnerable']}개")
        
        return result
    
    def _run_script(self, target: str, script_info: Dict) -> Optional[Dict]:
        """개별 스크립트 실행"""
        script_path = script_info.get('path')
        if not script_path or not os.path.exists(script_path):
            return None
        
        try:
            # 동적 모듈 로드
            spec = importlib.util.spec_from_file_location(
                script_info['name'], script_path
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # scan 함수 찾기
            scan_func = getattr(module, 'scan', None)
            if scan_func is None:
                return None
            
            # 실행
            result = scan_func(target)
            
            # 결과 정규화
            if isinstance(result, dict):
                result['script'] = script_info['name']
                result['category'] = script_info['category']
                return result
            
        except Exception as e:
            return {
                'script': script_info['name'],
                'category': script_info['category'],
                'status': 'ERROR',
                'error': str(e),
            }
        
        return None
    
    def get_scan_stats(self) -> Dict:
        """스캔 통계 반환"""
        if self.last_scan_result is None:
            return {}
        
        return {
            'target': self.last_scan_result['target'],
            'executed_modules': len(self.last_scan_result['executed_modules']),
            'skipped_modules': len(self.last_scan_result['skipped_modules']),
            'total_scripts': self.last_scan_result['summary']['total'],
            'vulnerabilities': self.last_scan_result['summary']['vulnerable'],
            'scan_time': self.last_scan_result['scan_time'],
        }


def smart_scan(target: str, timeout: float = 3.0, 
               modules: List[str] = None) -> Dict:
    """
    단순화된 인터페이스: 스마트 스캔 실행
    
    Args:
        target: 스캔 대상
        timeout: 타임아웃 (초)
        modules: 강제 지정할 모듈 (None이면 자동 감지)
        
    Returns:
        스캔 결과
    """
    scanner = SmartScanner(timeout=timeout)
    return scanner.scan(target, modules=modules)


if __name__ == '__main__':
    import warnings
    warnings.filterwarnings('ignore')
    
    if len(sys.argv) < 2:
        print("Usage: python smart_scanner.py <target> [modules...]")
        print("Example: python smart_scanner.py https://example.com")
        print("Example: python smart_scanner.py https://example.com web db")
        sys.exit(1)
    
    target = sys.argv[1]
    modules = sys.argv[2:] if len(sys.argv) > 2 else None
    
    print("=" * 60)
    print("SmartScanner - 인프라 기반 스마트 스캐너")
    print("=" * 60)
    print()
    
    scanner = SmartScanner()
    
    if modules:
        print(f"[*] 수동 모듈 지정: {', '.join(modules)}")
        result = scanner.scan(target, modules=modules, skip_detection=False)
    else:
        result = scanner.scan(target)
    
    print("\n" + "=" * 60)
    print("스캔 통계")
    print("=" * 60)
    stats = scanner.get_scan_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
