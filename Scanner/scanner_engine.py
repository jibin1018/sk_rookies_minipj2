"""
통합 스캐너 엔진
"""
import importlib
import os
from datetime import datetime


class VulnerabilityScanner:
    """웹 애플리케이션 취약점 스캐너"""
    
    # 웹 취약점 테스트 목록 (모듈명, 테스트명, 심각도)
    WEB_TESTS = [
        ('sqli', 'SQL Injection', 'CRITICAL'),
        ('xss', 'Cross-Site Scripting', 'HIGH'),
        ('path_traversal', 'Path Traversal', 'HIGH'),
        ('file_upload', 'File Upload', 'CRITICAL'),
        ('command_injection', 'Command Injection', 'CRITICAL'),
        ('xxe', 'XXE', 'HIGH'),
        ('deserialization', 'Deserialization', 'CRITICAL'),
        ('input_bypass', 'Input Bypass', 'MEDIUM'),
        ('access_control', 'Access Control', 'CRITICAL'),
        ('crypto_failures', 'Crypto Failures', 'CRITICAL'),
        ('auth_failures', 'Auth Failures', 'HIGH'),
        ('security_misconfig', 'Security Misconfig', 'HIGH'),
        ('ssrf', 'SSRF', 'MEDIUM'),
        ('cors_csrf', 'CORS/CSRF', 'MEDIUM'),
        ('insecure_design', 'Insecure Design', 'HIGH'),
        ('vulnerable_components', 'Vulnerable Components', 'MEDIUM'),
        ('integrity_failures', 'Integrity Failures', 'MEDIUM'),
        ('logging_failures', 'Logging Failures', 'LOW'),
    ]
    
    def __init__(self, target_url, scan_status=None, scan_id=None, scan_types=['all']):
        self.target_url = target_url
        self.scan_status = scan_status
        self.scan_id = scan_id
        self.scan_types = scan_types

    def scan_all(self):
        """모든 웹 취약점 스캔 실행"""
        results = []
        total_tests = len([t for t in self.WEB_TESTS if self.should_run_test(t[0], self.scan_types)])
        completed = 0

        for module_name, test_name, severity in self.WEB_TESTS:
            # scan_types 필터링
            if not self.should_run_test(module_name, self.scan_types):
                continue

            # 진행률 업데이트
            if self.scan_status and self.scan_id:
                completed += 1
                progress = int((completed / total_tests) * 100)
                self.scan_status[self.scan_id]['progress'] = progress
                self.scan_status[self.scan_id]['current_test'] = f'{test_name} 진단 중...'
            
            try:
                # 동적으로 모듈 import
                module = importlib.import_module(f'modules.web.{module_name}')
                
                # scan 함수 실행
                result = module.scan(self.target_url)
                results.append(result)
                
                print(f"[✓] {test_name} 완료")
                
            except Exception as e:
                print(f"[✗] {test_name} 실패: {str(e)}")
                results.append({
                    'name': test_name,
                    'status': 'ERROR',
                    'severity': severity,
                    'error': str(e),
                    'details': f'테스트 실행 중 오류 발생: {str(e)}'
                })
        
        return results
    
    def should_run_test(self, module_name, scan_types):
        """특정 테스트를 실행해야 하는지 확인"""
        if 'all' in scan_types:
            return True
        return module_name in scan_types
    
    def generate_report(self, results, output_dir='reports'):
        """보고서 생성 (TXT, JSON)"""
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'scan_report_{timestamp}'
        
        # TXT 보고서
        txt_path = os.path.join(output_dir, f'{filename}.txt')
        
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("보안 취약점 스캔 보고서\n")
            f.write("=" * 80 + "\n")
            f.write(f"대상: {self.target_url}\n")
            f.write(f"날짜: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            # 요약
            summary = self._calculate_summary(results)
            f.write("요약\n")
            f.write("-" * 80 + "\n")
            f.write(f"전체 테스트: {summary['total']}\n")
            f.write(f"취약점 발견: {summary['vulnerable']}\n")
            f.write(f"안전: {summary['safe']}\n")
            f.write(f"CRITICAL: {summary['critical']}\n")
            f.write(f"HIGH: {summary['high']}\n")
            f.write(f"위험 점수: {summary['risk_score']}/100\n")
            f.write("\n")
            
            # 상세 결과
            f.write("상세 결과\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                f.write(f"[{result['name']}]\n")
                f.write(f"상태: {result['status']}\n")
                f.write(f"심각도: {result.get('severity', 'UNKNOWN')}\n")
                
                if result.get('vulnerabilities'):
                    f.write(f"발견된 취약점:\n")
                    for vuln in result['vulnerabilities']:
                        f.write(f"  - {vuln}\n")
                
                if result.get('recommendation'):
                    f.write(f"권장사항: {result['recommendation']}\n")
                
                if result.get('details'):
                    f.write(f"\n상세:\n{result['details']}\n")
                
                f.write("\n" + "-" * 80 + "\n\n")
        
        print(f"보고서 생성 완료: {txt_path}")
        return txt_path
    
    def _calculate_summary(self, results):
        """요약 통계 계산"""
        summary = {
            'total': len(results),
            'vulnerable': 0,
            'safe': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'risk_score': 0
        }
        
        for result in results:
            if result['status'] == 'VULNERABLE':
                summary['vulnerable'] += 1
                
                severity = result.get('severity', 'MEDIUM')
                if severity == 'CRITICAL':
                    summary['critical'] += 1
                    summary['risk_score'] += 10
                elif severity == 'HIGH':
                    summary['high'] += 1
                    summary['risk_score'] += 5
                elif severity == 'MEDIUM':
                    summary['medium'] += 1
                    summary['risk_score'] += 2
                else:
                    summary['low'] += 1
                    summary['risk_score'] += 1
            elif result['status'] == 'SAFE':
                summary['safe'] += 1
        
        # 위험 점수 0-100 범위로 정규화
        summary['risk_score'] = min(summary['risk_score'], 100)
        
        return summary


class InfraScanner:
    """인프라 보안 스캐너 (SSH 기반)"""
    
    INFRA_TESTS = {
        'os': [
            ('linux_account', 'Linux 계정 관리'),
            ('linux_password', 'Linux 패스워드 정책'),
            ('linux_file_permission', 'Linux 파일 권한'),
            ('linux_service', 'Linux 서비스'),
            ('linux_log', 'Linux 로그 관리'),
        ],
        'web_server': [
            ('apache_config', 'Apache 설정'),
            ('nginx_config', 'Nginx 설정'),
        ],
        'was': [
            ('tomcat_config', 'Tomcat 설정'),
        ],
        'db': [
            ('mysql_config', 'MySQL 설정'),
        ]
    }
    
    def __init__(self, ssh_host, ssh_user, ssh_pass=None, ssh_port=22, ssh_key_file=None, scan_status=None, scan_id=None):
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass
        self.ssh_port = ssh_port
        self.ssh_key_file = ssh_key_file
        self.scan_status = scan_status
        self.scan_id = scan_id
    
    def scan_infrastructure(self, categories=['all']):
        """인프라 보안 스캔 실행"""
        results = []
        
        # 카테고리 필터링
        scan_categories = self.INFRA_TESTS.keys() if 'all' in categories else categories
        
        for category in scan_categories:
            if category not in self.INFRA_TESTS:
                continue
            
            for module_name, test_name in self.INFRA_TESTS[category]:
                try:
                    # 동적 import
                    module = importlib.import_module(f'modules.{category}.{module_name}')
                    
                    # scan 함수 실행
                    result = module.scan(
                        self.ssh_host,
                        self.ssh_user,
                        self.ssh_pass,
                        self.ssh_port,
                        self.ssh_key_file
                    )
                    results.append(result)
                    
                    print(f"[✓] {test_name} 완료")
                    
                except Exception as e:
                    print(f"[✗] {test_name} 실패: {str(e)}")
                    results.append({
                        'name': test_name,
                        'status': 'ERROR',
                        'severity': 'ERROR',
                        'error': str(e),
                        'details': f'테스트 실행 중 오류: {str(e)}'
                    })
        
        return results

    def generate_report(self, results, output_dir='reports'):
        """보고서 생성 (TXT)"""
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'infra_scan_report_{timestamp}'
        
        # TXT 보고서
        txt_path = os.path.join(output_dir, f'{filename}.txt')
        
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("인프라 보안 진단 보고서\n")
            f.write("=" * 80 + "\n")
            f.write(f"대상: {self.ssh_host}\n")
            f.write(f"날짜: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            # 요약
            summary = self._calculate_summary(results)
            f.write("요약\n")
            f.write("-" * 80 + "\n")
            f.write(f"전체 테스트: {summary['total']}\n")
            f.write(f"취약점 발견: {summary['vulnerable']}\n")
            f.write(f"양호: {summary['safe']}\n")
            f.write(f"CRITICAL: {summary['critical']}\n")
            f.write(f"HIGH: {summary['high']}\n")
            f.write(f"위험 점수: {summary['risk_score']}/100\n")
            f.write("\n")
            
            # 상세 결과
            f.write("상세 결과\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                f.write(f"[{result['name']}]\n")
                f.write(f"상태: {result['status']}\n")
                f.write(f"심각도: {result.get('severity', 'UNKNOWN')}\n")
                
                if result.get('vulnerabilities'):
                    f.write(f"발견된 취약점:\n")
                    for vuln in result['vulnerabilities']:
                        f.write(f"  - {vuln}\n")
                
                if result.get('recommendation'):
                    f.write(f"권장사항: {result['recommendation']}\n")
                
                if result.get('details'):
                    f.write(f"\n상세:\n{result['details']}\n")
                
                f.write("\n" + "-" * 80 + "\n\n")
        
        print(f"보고서 생성 완료: {txt_path}")
        return txt_path
    
    def _calculate_summary(self, results):
        """요약 통계 계산"""
        summary = {
            'total': len(results),
            'vulnerable': 0,
            'safe': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'risk_score': 0
        }
        
        for result in results:
            if result['status'] == 'VULNERABLE':
                summary['vulnerable'] += 1
                
                severity = result.get('severity', 'MEDIUM')
                if severity == 'CRITICAL':
                    summary['critical'] += 1
                    summary['risk_score'] += 10
                elif severity == 'HIGH':
                    summary['high'] += 1
                    summary['risk_score'] += 5
                elif severity == 'MEDIUM':
                    summary['medium'] += 1
                    summary['risk_score'] += 2
                else:
                    summary['low'] += 1
                    summary['risk_score'] += 1
            elif result['status'] == 'SAFE':
                summary['safe'] += 1
        
        # 위험 점수 0-100 범위로 정규화
        summary['risk_score'] = min(summary['risk_score'], 100)
        
        return summary