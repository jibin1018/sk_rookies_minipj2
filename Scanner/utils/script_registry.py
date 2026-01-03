#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
스크립트 레지스트리

스캔 스크립트의 메타데이터 관리 및 선별 실행을 위한 유틸리티
"""

import os
import importlib
import importlib.util
from typing import Dict, List, Optional, Set
from pathlib import Path


# 스크립트 카테고리 → 필요 서비스 매핑
CATEGORY_REQUIREMENTS = {
    'web': {
        'services': ['http', 'https'],
        'description': '웹 애플리케이션 취약점 스캔',
    },
    'web_server': {
        'services': ['http', 'https', 'nginx', 'apache', 'iis'],
        'description': '웹 서버 설정 점검',
    },
    'was': {
        'services': ['tomcat', 'jboss', 'weblogic', 'php', 'java', 'express'],
        'description': 'WAS 취약점 점검',
    },
    'db': {
        'services': ['mysql', 'mariadb', 'postgresql', 'mongodb', 'redis', 'mssql', 'oracle'],
        'description': '데이터베이스 보안 점검',
    },
    'os': {
        'services': ['ssh', 'linux', 'ubuntu', 'centos', 'debian'],
        'description': 'OS 보안 설정 점검',
    },
    'network': {
        'services': ['dns', 'ldap', 'ftp', 'smtp'],
        'description': '네트워크 서비스 점검',
    },
    'cloud': {
        'services': ['aws', 'gcp', 'azure'],
        'description': '클라우드 보안 점검',
    },
    'framework': {
        'services': ['http', 'https'],
        'description': '프레임워크 취약점 점검',
    },
}


class ScriptRegistry:
    """스캔 스크립트 레지스트리"""
    
    def __init__(self, modules_dir: str = None):
        """
        Args:
            modules_dir: modules 디렉토리 경로 (기본: Scanner/modules)
        """
        if modules_dir is None:
            # 현재 파일 기준으로 modules 디렉토리 찾기
            current_dir = Path(__file__).parent.parent
            modules_dir = current_dir / 'modules'
        
        self.modules_dir = Path(modules_dir)
        self._scripts = {}
        self._loaded = False
    
    def discover_scripts(self) -> Dict[str, List[Dict]]:
        """
        modules 디렉토리에서 스크립트 탐색
        
        Returns:
            카테고리별 스크립트 목록
        """
        if self._loaded:
            return self._scripts
        
        self._scripts = {}
        
        # 각 카테고리 디렉토리 순회
        for category_dir in self.modules_dir.iterdir():
            if not category_dir.is_dir():
                continue
            if category_dir.name.startswith('_') or category_dir.name.startswith('.'):
                continue
            
            category = category_dir.name
            self._scripts[category] = []
            
            # Python 파일 탐색
            for script_file in category_dir.glob('*.py'):
                if script_file.name.startswith('_'):
                    continue
                
                script_info = self._extract_script_info(script_file, category)
                if script_info:
                    self._scripts[category].append(script_info)
        
        self._loaded = True
        return self._scripts
    
    def _extract_script_info(self, script_path: Path, category: str) -> Optional[Dict]:
        """스크립트 파일에서 메타데이터 추출"""
        try:
            # 파일 내용 읽기
            content = script_path.read_text(encoding='utf-8')
            
            # 기본 정보
            info = {
                'path': str(script_path),
                'filename': script_path.name,
                'name': script_path.stem,
                'category': category,
                'has_scan_function': 'def scan(' in content or 'def scan_' in content,
            }
            
            # SCRIPT_META 추출 시도
            if 'SCRIPT_META' in content:
                info['has_meta'] = True
                # 간단한 파싱 (정교한 파싱은 실제 임포트 필요)
                if "'id':" in content or '"id":' in content:
                    info['has_id'] = True
            else:
                info['has_meta'] = False
            
            # docstring에서 설명 추출
            if '"""' in content:
                start = content.find('"""') + 3
                end = content.find('"""', start)
                if end > start:
                    docstring = content[start:end].strip()
                    # 첫 줄만 추출
                    first_line = docstring.split('\n')[0].strip()
                    if first_line:
                        info['description'] = first_line
            
            return info
            
        except Exception as e:
            return None
    
    def filter_by_services(self, detected_services: List[str], 
                           detected_products: List[str] = None) -> Dict[str, List[Dict]]:
        """
        감지된 서비스 기반으로 스크립트 필터링
        
        Args:
            detected_services: 감지된 서비스 목록 (예: ['http', 'mysql', 'ssh'])
            detected_products: 감지된 제품 목록 (예: ['nginx', 'php'])
            
        Returns:
            실행할 카테고리별 스크립트 목록
        """
        if not self._loaded:
            self.discover_scripts()
        
        all_detected = set(detected_services or [])
        if detected_products:
            all_detected.update(detected_products)
        
        filtered = {}
        
        for category, scripts in self._scripts.items():
            # 카테고리 요구사항 확인
            requirements = CATEGORY_REQUIREMENTS.get(category, {})
            required_services = set(requirements.get('services', []))
            
            # 교집합이 있으면 해당 카테고리 포함
            if required_services & all_detected:
                filtered[category] = scripts
            
            # web 카테고리는 http/https가 있으면 포함
            elif category == 'web' and {'http', 'https'} & all_detected:
                filtered[category] = scripts
        
        return filtered
    
    def filter_by_modules(self, modules: List[str]) -> Dict[str, List[Dict]]:
        """
        모듈 이름으로 스크립트 필터링
        
        Args:
            modules: 실행할 모듈 목록 (예: ['web', 'db', 'os'])
            
        Returns:
            실행할 카테고리별 스크립트 목록
        """
        if not self._loaded:
            self.discover_scripts()
        
        return {
            category: scripts 
            for category, scripts in self._scripts.items()
            if category in modules
        }
    
    def get_stats(self) -> Dict:
        """스크립트 통계 반환"""
        if not self._loaded:
            self.discover_scripts()
        
        stats = {
            'total': 0,
            'by_category': {},
            'with_scan_function': 0,
            'with_meta': 0,
        }
        
        for category, scripts in self._scripts.items():
            stats['by_category'][category] = len(scripts)
            stats['total'] += len(scripts)
            stats['with_scan_function'] += sum(1 for s in scripts if s.get('has_scan_function'))
            stats['with_meta'] += sum(1 for s in scripts if s.get('has_meta'))
        
        return stats
    
    def get_script_count(self, modules: List[str] = None) -> int:
        """지정된 모듈의 스크립트 수 반환"""
        if not self._loaded:
            self.discover_scripts()
        
        if modules is None:
            return sum(len(scripts) for scripts in self._scripts.values())
        
        return sum(
            len(scripts) for category, scripts in self._scripts.items()
            if category in modules
        )


def get_scripts_for_target(detected_services: List[str], 
                           detected_products: List[str] = None) -> Dict[str, List[Dict]]:
    """
    단순화된 인터페이스: 대상에 맞는 스크립트 반환
    
    Args:
        detected_services: 감지된 서비스 목록
        detected_products: 감지된 제품 목록
        
    Returns:
        카테고리별 스크립트 목록
    """
    registry = ScriptRegistry()
    return registry.filter_by_services(detected_services, detected_products)


if __name__ == '__main__':
    print("[*] 스크립트 레지스트리 테스트\n")
    
    registry = ScriptRegistry()
    scripts = registry.discover_scripts()
    
    stats = registry.get_stats()
    print("=" * 60)
    print(f"총 스크립트: {stats['total']}개")
    print(f"scan 함수 있음: {stats['with_scan_function']}개")
    print(f"메타데이터 있음: {stats['with_meta']}개")
    print("=" * 60)
    
    print("\n카테고리별:")
    for category, count in stats['by_category'].items():
        print(f"  - {category}: {count}개")
    
    # 필터링 테스트
    print("\n[*] 필터링 테스트: http + mysql")
    filtered = registry.filter_by_services(['http', 'mysql'])
    print(f"선별된 카테고리: {list(filtered.keys())}")
    print(f"선별된 스크립트 수: {sum(len(s) for s in filtered.values())}개")
