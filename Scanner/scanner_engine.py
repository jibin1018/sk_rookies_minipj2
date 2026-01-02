"""
통합 스캐너 엔진

인프라 인식 기반 선별적 스캔을 지원합니다.
- 인프라 탐지: 대상 시스템의 인프라 타입 자동 식별
- 선별적 스캔: 해당 인프라에 맞는 스크립트만 실행
"""
import importlib
import os
import time
from datetime import datetime

from infra_detector import InfraDetector
from infra_mapping import get_scripts_for_infra


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
        # 새로 추가된 취약점 스캐너
        ('security_headers', 'Security Headers', 'MEDIUM'),
        ('information_disclosure', 'Information Disclosure', 'MEDIUM'),
        ('idor', 'IDOR', 'CRITICAL'),
        ('jwt_vulnerabilities', 'JWT Vulnerabilities', 'CRITICAL'),
        ('rate_limiting', 'Rate Limiting', 'HIGH'),
        ('file_upload_bypass', 'File Upload Bypass', 'CRITICAL'),
        ('business_logic', 'Business Logic', 'HIGH'),
        ('mass_assignment', 'Mass Assignment', 'HIGH'),
        ('open_redirect', 'Open Redirect', 'MEDIUM'),
        ('http_method_abuse', 'HTTP Method Abuse', 'MEDIUM'),
        ('host_header_injection', 'Host Header Injection', 'MEDIUM'),
        ('http_parameter_pollution', 'HTTP Parameter Pollution', 'MEDIUM'),
        ('graphql_security', 'GraphQL Security', 'MEDIUM'),
    ]
    
    def __init__(self, target_url, scan_status=None, scan_id=None, scan_types=['all'], 
                 use_infra_detection=False):
        self.target_url = target_url
        self.scan_status = scan_status
        self.scan_id = scan_id
        self.scan_types = scan_types
        self.use_infra_detection = use_infra_detection
        self.infra_profile = None
        self.metrics = {
            'start_time': None,
            'end_time': None,
            'executed': 0,
            'skipped': 0,
            'total_duration': 0,
        }
        self._allowed_scripts = None

    def scan_all(self):
        """모든 웹 취약점 스캔 실행"""
        results = []
        self.metrics['start_time'] = time.time()
        
        # 인프라 탐지 (옵션 활성화 시)
        if self.use_infra_detection:
            print("[*] 인프라 탐지 시작...")
            detector = InfraDetector()
            self.infra_profile = detector.detect(self.target_url)
            self._allowed_scripts = get_scripts_for_infra(self.infra_profile)
            
            print(f"[✓] 인프라 탐지 완료:")
            print(f"    - 웹 서버: {self.infra_profile.get('web_server') or 'Unknown'}")
            print(f"    - 언어: {self.infra_profile.get('language') or 'Unknown'}")
            print(f"    - 프레임워크: {self.infra_profile.get('framework') or 'Unknown'}")
            print(f"    - 실행할 스크립트 수: {len(self._allowed_scripts)}")
        
        # 실행할 테스트 필터링
        tests_to_run = [t for t in self.WEB_TESTS if self.should_run_test(t[0], self.scan_types)]
        total_tests = len(tests_to_run)
        completed = 0

        for module_name, test_name, severity in self.WEB_TESTS:
            module_path = f'modules.web.{module_name}'
            
            # scan_types 필터링
            if not self.should_run_test(module_name, self.scan_types):
                continue
            
            # 인프라 기반 필터링
            if self.use_infra_detection and self._allowed_scripts:
                if module_path not in self._allowed_scripts:
                    print(f"[⏭] {test_name} 스킵 (인프라 불일치)")
                    self.metrics['skipped'] += 1
                    continue

            # 진행률 업데이트
            if self.scan_status and self.scan_id:
                completed += 1
                progress = int((completed / total_tests) * 100)
                self.scan_status[self.scan_id]['progress'] = progress
                self.scan_status[self.scan_id]['current_test'] = f'{test_name} 진단 중...'
            
            try:
                # 동적으로 모듈 import
                module = importlib.import_module(module_path)
                
                # scan 함수 실행
                result = module.scan(self.target_url)
                results.append(result)
                self.metrics['executed'] += 1
                
                print(f"[✓] {test_name} 완료")
                
            except Exception as e:
                print(f"[✗] {test_name} 실패: {str(e)}")
                self.metrics['executed'] += 1
                results.append({
                    'name': test_name,
                    'status': 'ERROR',
                    'severity': severity,
                    'error': str(e),
                    'details': f'테스트 실행 중 오류 발생: {str(e)}'
                })
        
        self.metrics['end_time'] = time.time()
        self.metrics['total_duration'] = self.metrics['end_time'] - self.metrics['start_time']
        
        # 성능 메트릭 출력
        print(f"\n[📊] 스캔 완료 - 실행: {self.metrics['executed']}, "
              f"스킵: {self.metrics['skipped']}, "
              f"소요시간: {self.metrics['total_duration']:.2f}초")
        
        return results
    
    def should_run_test(self, module_name, scan_types):
        """특정 테스트를 실행해야 하는지 확인"""
        if 'all' in scan_types:
            return True
        return module_name in scan_types
    
    def generate_report(self, results, output_dir='reports'):
        """보고서 생성 (Markdown)"""
        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'scan_report_{timestamp}'

        # Markdown 보고서
        md_path = os.path.abspath(os.path.join(output_dir, f'{filename}.md'))

        with open(md_path, 'w', encoding='utf-8') as f:
            # 제목
            f.write("# 🔒 보안 취약점 스캔 보고서\n\n")
            f.write(f"**대상**: `{self.target_url}`  \n")
            f.write(f"**날짜**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")

            # 요약
            summary = self._calculate_summary(results)
            f.write("## 📊 요약\n\n")
            f.write("| 항목 | 개수 |\n")
            f.write("|------|------|\n")
            f.write(f"| 전체 테스트 | {summary['total']} |\n")
            f.write(f"| 취약점 발견 | **{summary['vulnerable']}** |\n")
            f.write(f"| 안전 | {summary['safe']} |\n")
            f.write(f"| 🔴 CRITICAL | {summary['critical']} |\n")
            f.write(f"| 🟠 HIGH | {summary['high']} |\n")
            f.write(f"| 🟡 MEDIUM | {summary['medium']} |\n")
            f.write(f"| 🟢 LOW | {summary['low']} |\n")
            f.write(f"| **위험 점수** | **{summary['risk_score']}/100** |\n\n")

            # 심각도별 아이콘 매핑
            severity_icons = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢',
                'UNKNOWN': '⚪'
            }

            # 상태별 아이콘 매핑
            status_icons = {
                'VULNERABLE': '❌',
                'SAFE': '✅',
                'ERROR': '⚠️'
            }

            # 상세 결과
            f.write("---\n\n")
            f.write("## 📋 상세 결과\n\n")

            for idx, result in enumerate(results, 1):
                severity = result.get('severity', 'UNKNOWN')
                status = result.get('status', 'UNKNOWN')

                severity_icon = severity_icons.get(severity, '⚪')
                status_icon = status_icons.get(status, '❓')

                f.write(f"### {idx}. {status_icon} {result['name']}\n\n")
                f.write(f"- **상태**: {status_icon} `{status}`\n")
                f.write(f"- **심각도**: {severity_icon} `{severity}`\n")

                if result.get('vulnerabilities'):
                    f.write(f"\n**발견된 취약점**:\n\n")
                    for vuln in result['vulnerabilities']:
                        f.write(f"- {vuln}\n")
                    f.write("\n")

                if result.get('recommendation'):
                    f.write(f"**권장사항**: {result['recommendation']}\n\n")

                if result.get('details'):
                    f.write(f"<details>\n<summary>상세 정보 보기</summary>\n\n")
                    f.write(f"```\n{result['details']}\n```\n\n")
                    f.write(f"</details>\n\n")

                f.write("---\n\n")

        print(f"보고서 생성 완료: {md_path}")
        return md_path
    
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
    """인프라 보안 스캐너 (SSH 기반)
    
    포트 스캔을 통해 실행 중인 서비스를 자동 탐지하고,
    해당 서비스에 맞는 스크립트만 선별 실행합니다.
    """
    
    INFRA_TESTS = {
        'os': [
            ('linux_account', 'Linux 계정 관리'),
            ('linux_password', 'Linux 패스워드 정책'),
            ('linux_file_permission', 'Linux 파일 권한'),
            ('linux_service', 'Linux 서비스'),
            ('linux_log', 'Linux 로그 관리'),
            ('linux_firewall', 'Linux 방화벽'),
            ('linux_ssh', 'Linux SSH 보안'),
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
    
    # 포트 → 테스트 매핑
    PORT_SERVICE_MAPPING = {
        # 데이터베이스
        3306: ('db', 'mysql_config'),
        5432: ('db', 'postgresql_config'),
        27017: ('db', 'mongodb_config'),
        1433: ('db', 'mssql_config'),
        1521: ('db', 'oracle_config'),
        6379: ('db', 'redis_config'),
        9200: ('db', 'elasticsearch_config'),
        # WAS
        8080: ('was', 'tomcat_config'),
        8443: ('was', 'tomcat_config'),
        8009: ('was', 'tomcat_config'),
    }
    
    def __init__(self, ssh_host, ssh_user, ssh_pass=None, ssh_port=22, 
                 ssh_key_file=None, scan_status=None, scan_id=None,
                 use_discovery=False):
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass
        self.ssh_port = ssh_port
        self.ssh_key_file = ssh_key_file
        self.scan_status = scan_status
        self.scan_id = scan_id
        self.use_discovery = use_discovery
        self.discovered_services = {}
        self.metrics = {
            'start_time': None,
            'end_time': None,
            'executed': 0,
            'skipped': 0,
            'total_duration': 0,
        }
    
    def discover_services(self):
        """포트 스캔으로 서비스 탐지"""
        try:
            from discovery.port_scanner import PortScanner
            
            print(f"[*] 포트 스캔 시작: {self.ssh_host}")
            scanner = PortScanner(timeout=1.0)
            result = scanner.scan_common_ports(self.ssh_host)
            
            print(f"[✓] 열린 포트: {result['total_open']}개")
            for port_info in result['open_ports']:
                print(f"    {port_info['port']}/tcp - {port_info['service']}")
            
            self.discovered_services = result
            return result
            
        except Exception as e:
            print(f"[✗] 포트 스캔 실패: {str(e)}")
            return {'open_ports': [], 'services': {}}
    
    def _get_tests_for_discovered_services(self):
        """발견된 서비스 기반 테스트 목록 생성"""
        tests_to_run = set()
        
        # OS 테스트는 항상 포함 (SSH 접속만 되면 가능)
        for test in self.INFRA_TESTS.get('os', []):
            tests_to_run.add(('os', test[0], test[1]))
        
        # 포트 기반 서비스 테스트 추가
        for port_info in self.discovered_services.get('open_ports', []):
            port = port_info['port']
            if port in self.PORT_SERVICE_MAPPING:
                category, module_name = self.PORT_SERVICE_MAPPING[port]
                # INFRA_TESTS에서 test_name 찾기
                for test in self.INFRA_TESTS.get(category, []):
                    if test[0] == module_name:
                        tests_to_run.add((category, test[0], test[1]))
                        break
        
        return list(tests_to_run)
    
    def scan_infrastructure(self, categories=['all']):
        """인프라 보안 스캔 실행"""
        results = []
        self.metrics['start_time'] = time.time()
        
        # Discovery 모드: 포트 스캔 후 선별 실행
        if self.use_discovery:
            print("[*] Discovery 모드 활성화")
            self.discover_services()
            tests_to_run = self._get_tests_for_discovered_services()
            
            print(f"[*] 선별된 테스트: {len(tests_to_run)}개")
            
            for category, module_name, test_name in tests_to_run:
                try:
                    module = importlib.import_module(f'modules.{category}.{module_name}')
                    result = module.scan(
                        self.ssh_host,
                        self.ssh_user,
                        self.ssh_pass,
                        self.ssh_port,
                        self.ssh_key_file
                    )
                    results.append(result)
                    self.metrics['executed'] += 1
                    print(f"[✓] {test_name} 완료")
                    
                except Exception as e:
                    print(f"[✗] {test_name} 실패: {str(e)}")
                    self.metrics['executed'] += 1
                    results.append({
                        'name': test_name,
                        'status': 'ERROR',
                        'severity': 'ERROR',
                        'error': str(e),
                        'details': f'테스트 실행 중 오류: {str(e)}'
                    })
        else:
            # 기존 모드: 카테고리 기반 실행
            scan_categories = self.INFRA_TESTS.keys() if 'all' in categories else categories
            
            for category in scan_categories:
                if category not in self.INFRA_TESTS:
                    continue
                
                for module_name, test_name in self.INFRA_TESTS[category]:
                    try:
                        module = importlib.import_module(f'modules.{category}.{module_name}')
                        result = module.scan(
                            self.ssh_host,
                            self.ssh_user,
                            self.ssh_pass,
                            self.ssh_port,
                            self.ssh_key_file
                        )
                        results.append(result)
                        self.metrics['executed'] += 1
                        print(f"[✓] {test_name} 완료")
                        
                    except Exception as e:
                        print(f"[✗] {test_name} 실패: {str(e)}")
                        self.metrics['executed'] += 1
                        results.append({
                            'name': test_name,
                            'status': 'ERROR',
                            'severity': 'ERROR',
                            'error': str(e),
                            'details': f'테스트 실행 중 오류: {str(e)}'
                        })
        
        self.metrics['end_time'] = time.time()
        self.metrics['total_duration'] = self.metrics['end_time'] - self.metrics['start_time']
        
        print(f"\n[📊] 인프라 스캔 완료 - 실행: {self.metrics['executed']}, "
              f"소요시간: {self.metrics['total_duration']:.2f}초")
        
        return results

    def generate_report(self, results, output_dir='reports'):
        """보고서 생성 (Markdown)"""
        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'infra_scan_report_{timestamp}'

        # Markdown 보고서
        md_path = os.path.abspath(os.path.join(output_dir, f'{filename}.md'))

        with open(md_path, 'w', encoding='utf-8') as f:
            # 제목
            f.write("# 🖥️ 인프라 보안 진단 보고서\n\n")
            f.write(f"**대상**: `{self.ssh_host}`  \n")
            f.write(f"**날짜**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")

            # 요약
            summary = self._calculate_summary(results)
            f.write("## 📊 요약\n\n")
            f.write("| 항목 | 개수 |\n")
            f.write("|------|------|\n")
            f.write(f"| 전체 테스트 | {summary['total']} |\n")
            f.write(f"| 취약점 발견 | **{summary['vulnerable']}** |\n")
            f.write(f"| 양호 | {summary['safe']} |\n")
            f.write(f"| 🔴 CRITICAL | {summary['critical']} |\n")
            f.write(f"| 🟠 HIGH | {summary['high']} |\n")
            f.write(f"| 🟡 MEDIUM | {summary['medium']} |\n")
            f.write(f"| 🟢 LOW | {summary['low']} |\n")
            f.write(f"| **위험 점수** | **{summary['risk_score']}/100** |\n\n")

            # 심각도별 아이콘 매핑
            severity_icons = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢',
                'ERROR': '⚠️',
                'UNKNOWN': '⚪'
            }

            # 상태별 아이콘 매핑
            status_icons = {
                'VULNERABLE': '❌',
                'SAFE': '✅',
                'ERROR': '⚠️'
            }

            # 상세 결과
            f.write("---\n\n")
            f.write("## 📋 상세 결과\n\n")

            for idx, result in enumerate(results, 1):
                severity = result.get('severity', 'UNKNOWN')
                status = result.get('status', 'UNKNOWN')

                severity_icon = severity_icons.get(severity, '⚪')
                status_icon = status_icons.get(status, '❓')

                f.write(f"### {idx}. {status_icon} {result['name']}\n\n")
                f.write(f"- **상태**: {status_icon} `{status}`\n")
                f.write(f"- **심각도**: {severity_icon} `{severity}`\n")

                if result.get('vulnerabilities'):
                    f.write(f"\n**발견된 취약점**:\n\n")
                    for vuln in result['vulnerabilities']:
                        f.write(f"- {vuln}\n")
                    f.write("\n")

                if result.get('recommendation'):
                    f.write(f"**권장사항**: {result['recommendation']}\n\n")

                if result.get('details'):
                    f.write(f"<details>\n<summary>상세 정보 보기</summary>\n\n")
                    f.write(f"```\n{result['details']}\n```\n\n")
                    f.write(f"</details>\n\n")

                f.write("---\n\n")

        print(f"보고서 생성 완료: {md_path}")
        return md_path
    
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