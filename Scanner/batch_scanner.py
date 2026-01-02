"""
URL 배치 스캐너

다수의 URL을 일괄적으로 스캔하고 통합 보고서를 생성합니다.
"""

import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner_engine import VulnerabilityScanner
from infra_detector import InfraDetector


class BatchScanner:
    """URL 배치 스캐너"""
    
    def __init__(self, max_workers: int = 3):
        """
        Args:
            max_workers: 동시에 스캔할 최대 URL 수
        """
        self.max_workers = max_workers
        self.url_queue = []
        self.results = {}
        self.infra_profiles = {}
        self.start_time = None
        self.end_time = None
    
    def add_url(self, url: str):
        """단일 URL 추가"""
        if url and url not in self.url_queue:
            self.url_queue.append(url)
    
    def add_urls(self, urls: list):
        """URL 목록 추가"""
        for url in urls:
            self.add_url(url)
    
    def clear_queue(self):
        """URL 큐 초기화"""
        self.url_queue = []
        self.results = {}
        self.infra_profiles = {}
    
    def scan_all(self, use_infra_detection: bool = True, 
                 scan_types: list = None) -> dict:
        """
        모든 URL 순차 스캔
        
        Args:
            use_infra_detection: 인프라 탐지 활성화 여부
            scan_types: 실행할 스캔 타입 (기본: ['all'])
            
        Returns:
            URL별 스캔 결과 딕셔너리
        """
        if scan_types is None:
            scan_types = ['all']
        
        self.start_time = time.time()
        total_urls = len(self.url_queue)
        
        print(f"\n{'='*60}")
        print(f"[📋] 배치 스캔 시작: {total_urls}개 URL")
        print(f"[⚙️] 인프라 탐지: {'활성화' if use_infra_detection else '비활성화'}")
        print(f"{'='*60}\n")
        
        for idx, url in enumerate(self.url_queue, 1):
            print(f"\n[{idx}/{total_urls}] 스캔 시작: {url}")
            print("-" * 50)
            
            try:
                # 스캐너 생성 및 실행
                scanner = VulnerabilityScanner(
                    target_url=url,
                    scan_types=scan_types,
                    use_infra_detection=use_infra_detection
                )
                
                scan_results = scanner.scan_all()
                
                # 결과 저장
                self.results[url] = {
                    'status': 'completed',
                    'results': scan_results,
                    'metrics': scanner.metrics,
                    'summary': scanner._calculate_summary(scan_results),
                }
                
                # 인프라 프로필 저장
                if scanner.infra_profile:
                    self.infra_profiles[url] = scanner.infra_profile
                
            except Exception as e:
                print(f"[✗] 스캔 실패: {str(e)}")
                self.results[url] = {
                    'status': 'error',
                    'error': str(e),
                    'results': [],
                }
        
        self.end_time = time.time()
        total_duration = self.end_time - self.start_time
        
        print(f"\n{'='*60}")
        print(f"[✓] 배치 스캔 완료")
        print(f"    - 총 URL: {total_urls}개")
        print(f"    - 성공: {sum(1 for r in self.results.values() if r['status'] == 'completed')}개")
        print(f"    - 실패: {sum(1 for r in self.results.values() if r['status'] == 'error')}개")
        print(f"    - 총 소요시간: {total_duration:.2f}초")
        print(f"{'='*60}\n")
        
        return self.results
    
    def scan_parallel(self, use_infra_detection: bool = True,
                      scan_types: list = None) -> dict:
        """
        병렬 스캔 (주의: 대상 서버에 부하 발생 가능)
        
        Args:
            use_infra_detection: 인프라 탐지 활성화 여부
            scan_types: 실행할 스캔 타입
            
        Returns:
            URL별 스캔 결과 딕셔너리
        """
        if scan_types is None:
            scan_types = ['all']
        
        self.start_time = time.time()
        total_urls = len(self.url_queue)
        
        print(f"\n[📋] 병렬 배치 스캔 시작: {total_urls}개 URL (동시 {self.max_workers}개)")
        
        def scan_single(url):
            scanner = VulnerabilityScanner(
                target_url=url,
                scan_types=scan_types,
                use_infra_detection=use_infra_detection
            )
            results = scanner.scan_all()
            return url, results, scanner.metrics, scanner.infra_profile
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(scan_single, url): url for url in self.url_queue}
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    url, results, metrics, infra_profile = future.result()
                    self.results[url] = {
                        'status': 'completed',
                        'results': results,
                        'metrics': metrics,
                    }
                    if infra_profile:
                        self.infra_profiles[url] = infra_profile
                except Exception as e:
                    self.results[url] = {
                        'status': 'error',
                        'error': str(e),
                    }
        
        self.end_time = time.time()
        return self.results
    
    def generate_summary_report(self, output_dir: str = 'reports') -> str:
        """
        전체 결과 요약 보고서 생성
        
        Args:
            output_dir: 보고서 저장 디렉토리
            
        Returns:
            생성된 보고서 파일 경로
        """
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'batch_scan_report_{timestamp}.md'
        filepath = os.path.join(output_dir, filename)
        
        total_duration = (self.end_time - self.start_time) if self.end_time else 0
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("# 🔒 배치 보안 스캔 보고서\n\n")
            f.write(f"**생성일시**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**스캔 URL 수**: {len(self.url_queue)}개\n")
            f.write(f"**총 소요시간**: {total_duration:.2f}초\n\n")
            f.write("---\n\n")
            
            # 전체 요약
            f.write("## 📊 전체 요약\n\n")
            f.write("| URL | 상태 | 취약점 | 위험점수 |\n")
            f.write("|-----|------|--------|----------|\n")
            
            for url, result in self.results.items():
                status = "✅ 완료" if result['status'] == 'completed' else "❌ 실패"
                if result['status'] == 'completed':
                    summary = result.get('summary', {})
                    vulns = summary.get('vulnerable', 0)
                    score = summary.get('risk_score', 0)
                    f.write(f"| `{url}` | {status} | {vulns} | {score}/100 |\n")
                else:
                    f.write(f"| `{url}` | {status} | - | - |\n")
            
            f.write("\n---\n\n")
            
            # 인프라 프로필 요약
            if self.infra_profiles:
                f.write("## 🖥️ 인프라 프로필\n\n")
                f.write("| URL | 웹서버 | 언어 | 프레임워크 | DB |\n")
                f.write("|-----|--------|------|------------|----|\n")
                
                for url, profile in self.infra_profiles.items():
                    ws = profile.get('web_server') or '-'
                    lang = profile.get('language') or '-'
                    fw = profile.get('framework') or '-'
                    db = profile.get('database') or '-'
                    f.write(f"| `{url}` | {ws} | {lang} | {fw} | {db} |\n")
                
                f.write("\n---\n\n")
            
            # URL별 상세 결과
            f.write("## 📋 URL별 상세 결과\n\n")
            
            for url, result in self.results.items():
                f.write(f"### {url}\n\n")
                
                if result['status'] == 'error':
                    f.write(f"❌ **스캔 실패**: {result.get('error', 'Unknown error')}\n\n")
                    continue
                
                metrics = result.get('metrics', {})
                f.write(f"- **실행 스크립트**: {metrics.get('executed', 0)}개\n")
                f.write(f"- **스킵 스크립트**: {metrics.get('skipped', 0)}개\n")
                f.write(f"- **소요시간**: {metrics.get('total_duration', 0):.2f}초\n\n")
                
                # 취약점 목록
                vulns = [r for r in result.get('results', []) if r.get('status') == 'VULNERABLE']
                if vulns:
                    f.write("**발견된 취약점**:\n\n")
                    for v in vulns:
                        severity = v.get('severity', 'UNKNOWN')
                        f.write(f"- [{severity}] {v.get('name', 'Unknown')}\n")
                    f.write("\n")
                else:
                    f.write("✅ 발견된 취약점 없음\n\n")
                
                f.write("---\n\n")
        
        print(f"[✓] 배치 보고서 생성: {filepath}")
        return filepath
    
    def get_status(self) -> dict:
        """현재 배치 스캔 상태 반환"""
        completed = sum(1 for r in self.results.values() if r['status'] == 'completed')
        errors = sum(1 for r in self.results.values() if r['status'] == 'error')
        
        return {
            'total_urls': len(self.url_queue),
            'completed': completed,
            'errors': errors,
            'pending': len(self.url_queue) - completed - errors,
            'infra_profiles': self.infra_profiles,
        }


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python batch_scanner.py <url1> [url2] [url3] ...")
        sys.exit(1)
    
    urls = sys.argv[1:]
    
    batch = BatchScanner()
    batch.add_urls(urls)
    
    results = batch.scan_all(use_infra_detection=True)
    report_path = batch.generate_summary_report()
    
    print(f"\n보고서: {report_path}")
