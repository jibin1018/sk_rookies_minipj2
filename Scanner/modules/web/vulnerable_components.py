"""
A06: Vulnerable and Outdated Components
취약한 컴포넌트 및 라이브러리 탐지
"""
import requests
import re
import json

def scan(target_url):
    result = {
        'name': 'A06: Vulnerable and Outdated Components',
        'category': 'OWASP TOP 10 2025',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '정기적인 의존성 업데이트, 보안 스캔 도구(npm audit, OWASP Dependency-Check) 사용, CVE 모니터링',
        'details': ''
    }
    
    details = []
    
    # 1. 서버 헤더에서 버전 정보 탐지
    details.append("[컴포넌트-1] 서버 및 프레임워크 버전 정보 노출 확인")
    
    try:
        resp = requests.get(target_url, timeout=5)
        headers = resp.headers
        
        # Server 헤더
        if 'Server' in headers:
            server = headers['Server']
            details.append(f"  서버 정보: {server}")
            
            # 알려진 취약한 버전 패턴
            vulnerable_patterns = {
                'Apache/2.4.1': 'CVE-2012-0883 (취약)',
                'Apache/2.4.49': 'CVE-2021-41773 (Path Traversal)',
                'Apache/2.4.50': 'CVE-2021-42013 (Path Traversal)',
                'nginx/1.10': '오래된 버전 (취약점 가능성)',
                'nginx/1.6': 'CVE-2013-4547 (취약)',
                'Apache/2.2': '매우 오래된 버전 (EOL)',
                'Microsoft-IIS/6.0': 'CVE-2017-7269 (Buffer Overflow)',
                'Microsoft-IIS/7.0': '오래된 버전',
            }
            
            for pattern, desc in vulnerable_patterns.items():
                if pattern in server:
                    result['vulnerabilities'].append(f"취약한 서버 버전: {server} - {desc}")
                    details.append(f"  ✗ 취약: {desc}")
                    result['status'] = 'VULNERABLE'
                    break
            
            # 버전 번호 추출
            version_match = re.search(r'/([\d.]+)', server)
            if version_match and result['status'] == 'SAFE':
                details.append(f"  ⚠ 버전 정보 노출: {version_match.group(1)}")
        
        # X-Powered-By 헤더
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            result['vulnerabilities'].append(f"기술 스택 노출: {powered_by}")
            details.append(f"  ⚠ 정보 노출: X-Powered-By: {powered_by}")
            
            # 알려진 취약한 버전
            if 'Express' in powered_by:
                version_match = re.search(r'(\d+\.\d+\.\d+)', powered_by)
                if version_match:
                    version = version_match.group(1)
                    details.append(f"    Express 버전: {version}")
                    
                    # 4.x 미만은 취약
                    major_version = int(version.split('.')[0])
                    if major_version < 4:
                        result['vulnerabilities'].append(f"오래된 Express 버전: {version}")
                        details.append(f"    ✗ Express {version} - 알려진 취약점 다수")
                        result['status'] = 'VULNERABLE'
            
            # PHP 버전
            if 'PHP' in powered_by:
                version_match = re.search(r'PHP/([\d.]+)', powered_by)
                if version_match:
                    php_version = version_match.group(1)
                    details.append(f"    PHP 버전: {php_version}")
                    
                    # PHP 5.x는 EOL
                    if php_version.startswith('5.'):
                        result['vulnerabilities'].append(f"오래된 PHP: {php_version} (EOL)")
                        details.append(f"    ✗ PHP {php_version} - End of Life")
                        result['status'] = 'VULNERABLE'
        
        # X-AspNet-Version (ASP.NET)
        if 'X-AspNet-Version' in headers:
            aspnet_ver = headers['X-AspNet-Version']
            result['vulnerabilities'].append(f"ASP.NET 버전 노출: {aspnet_ver}")
            details.append(f"  ⚠ 정보 노출: X-AspNet-Version: {aspnet_ver}")
            
            # ASP.NET 4.0 미만
            if aspnet_ver.startswith(('2.', '3.')):
                result['vulnerabilities'].append(f"오래된 ASP.NET: {aspnet_ver}")
                details.append(f"    ✗ 취약한 버전")
                result['status'] = 'VULNERABLE'
        
        # X-AspNetMvc-Version
        if 'X-AspNetMvc-Version' in headers:
            mvc_ver = headers['X-AspNetMvc-Version']
            details.append(f"  ⚠ ASP.NET MVC 버전: {mvc_ver}")
            
    except Exception as e:
        details.append(f"  • 서버 헤더 확인 실패")
    
    # 2. JavaScript 라이브러리 버전 탐지
    details.append("\n[컴포넌트-2] 클라이언트 라이브러리 버전 확인")
    
    try:
        resp = requests.get(target_url, timeout=5)
        html = resp.text
        
        # jQuery 버전 탐지
        jquery_patterns = [
            r'jquery[/-](\d+\.\d+\.\d+)',
            r'jQuery\s+v(\d+\.\d+\.\d+)',
            r'jquery\.min\.js\?v=(\d+\.\d+\.\d+)',
        ]
        
        for pattern in jquery_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                jquery_version = match.group(1)
                details.append(f"  발견: jQuery {jquery_version}")
                
                # jQuery 1.x, 2.x는 취약 (CVE-2019-11358, CVE-2020-11022, CVE-2020-11023)
                major_version = int(jquery_version.split('.')[0])
                if major_version <= 2:
                    result['vulnerabilities'].append(f"취약한 jQuery: {jquery_version} (XSS 취약점)")
                    details.append(f"    ✗ jQuery {jquery_version} - CVE-2019-11358, CVE-2020-11022")
                    result['status'] = 'VULNERABLE'
                elif jquery_version.startswith('3.') and int(jquery_version.split('.')[1]) < 5:
                    result['vulnerabilities'].append(f"오래된 jQuery 3.x: {jquery_version}")
                    details.append(f"    ⚠ jQuery {jquery_version} - 업데이트 권장 (3.5+ 권장)")
                break
        
        # React 버전 탐지
        react_patterns = [
            r'react[/-](\d+\.\d+\.\d+)',
            r'react\.production\.min\.js\?v=(\d+\.\d+\.\d+)',
        ]
        
        for pattern in react_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                react_version = match.group(1)
                details.append(f"  발견: React {react_version}")
                
                # React 16 미만 (CVE-2018-6341)
                major_version = int(react_version.split('.')[0])
                if major_version < 16:
                    result['vulnerabilities'].append(f"오래된 React: {react_version}")
                    details.append(f"    ⚠ React {react_version} - 업데이트 권장")
                break
        
        # Angular 버전
        angular_patterns = [
            r'angular[/-](\d+\.\d+\.\d+)',
            r'@angular/core@(\d+\.\d+\.\d+)',
        ]
        
        for pattern in angular_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                angular_version = match.group(1)
                details.append(f"  발견: Angular {angular_version}")
                
                # AngularJS (1.x)는 EOL
                if angular_version.startswith('1.'):
                    result['vulnerabilities'].append(f"AngularJS 사용: {angular_version} (EOL)")
                    details.append(f"    ✗ AngularJS {angular_version} - 지원 종료됨")
                    result['status'] = 'VULNERABLE'
                break
        
        # Bootstrap 버전
        bootstrap_match = re.search(r'bootstrap[/-](\d+\.\d+\.\d+)', html, re.IGNORECASE)
        if bootstrap_match:
            bootstrap_version = bootstrap_match.group(1)
            details.append(f"  발견: Bootstrap {bootstrap_version}")
            
            # Bootstrap 3.x 이하 (CVE-2019-8331)
            major_version = int(bootstrap_version.split('.')[0])
            if major_version <= 3:
                result['vulnerabilities'].append(f"취약한 Bootstrap: {bootstrap_version}")
                details.append(f"    ✗ Bootstrap {bootstrap_version} - XSS 위험 (CVE-2019-8331)")
                result['status'] = 'VULNERABLE'
        
        # Vue.js 버전
        vue_match = re.search(r'vue[/-](\d+\.\d+\.\d+)', html, re.IGNORECASE)
        if vue_match:
            vue_version = vue_match.group(1)
            details.append(f"  발견: Vue.js {vue_version}")
            
            # Vue 2.x 미만
            major_version = int(vue_version.split('.')[0])
            if major_version < 2:
                result['vulnerabilities'].append(f"오래된 Vue.js: {vue_version}")
                details.append(f"    ⚠ Vue {vue_version} - 업데이트 권장")
        
        # Lodash 버전
        lodash_match = re.search(r'lodash[/-](\d+\.\d+\.\d+)', html, re.IGNORECASE)
        if lodash_match:
            lodash_version = lodash_match.group(1)
            details.append(f"  발견: Lodash {lodash_version}")
            
            # Lodash 4.17.11 미만 (CVE-2019-10744)
            if lodash_version < '4.17.11':
                result['vulnerabilities'].append(f"취약한 Lodash: {lodash_version}")
                details.append(f"    ✗ Lodash {lodash_version} - Prototype Pollution")
                result['status'] = 'VULNERABLE'
        
        # Moment.js (더 이상 유지보수 안 됨)
        moment_match = re.search(r'moment[/-](\d+\.\d+\.\d+)', html, re.IGNORECASE)
        if moment_match:
            moment_version = moment_match.group(1)
            result['vulnerabilities'].append(f"Moment.js 사용 (유지보수 중단)")
            details.append(f"  ⚠ Moment.js {moment_version} - 유지보수 중단됨 (Day.js 등으로 마이그레이션 권장)")
        
    except Exception as e:
        details.append(f"  • 클라이언트 라이브러리 탐지 실패")
    
    # 3. 알려진 취약한 경로 확인
    details.append("\n[컴포넌트-3] 취약한 컴포넌트 경로 확인")
    
    vulnerable_paths = [
        ('/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', 'PHPUnit RCE (CVE-2017-9841)'),
        ('/.git/config', 'Git 저장소 노출'),
        ('/composer.json', 'Composer 설정 노출'),
        ('/package.json', 'npm 패키지 정보 노출'),
        ('/.env', '환경 변수 파일 노출'),
        ('/web.config', 'IIS 설정 노출'),
        ('/elmah.axd', 'ELMAH 에러 로그 노출'),
        ('/trace.axd', 'ASP.NET 추적 정보'),
        ('/actuator/env', 'Spring Boot Actuator'),
        ('/actuator/health', 'Spring Boot Health'),
        ('/jolokia', 'Jolokia JMX'),
        ('/.well-known/security.txt', 'Security.txt'),
    ]
    
    for path, desc in vulnerable_paths:
        try:
            resp = requests.get(f"{target_url}{path}", timeout=5)
            
            if resp.status_code == 200 and len(resp.text) > 0:
                result['vulnerabilities'].append(f"민감한 파일 노출: {desc}")
                details.append(f"  ✗ 취약: {path} 접근 가능")
                result['status'] = 'VULNERABLE'
                
        except:
            pass
    
    # 4. package.json 내용 분석 (노출된 경우)
    details.append("\n[컴포넌트-4] 의존성 파일 분석")
    
    try:
        package_resp = requests.get(f"{target_url}/package.json", timeout=5)
        
        if package_resp.status_code == 200:
            try:
                package_data = json.loads(package_resp.text)
                dependencies = package_data.get('dependencies', {})
                
                details.append(f"  발견: package.json 노출 ({len(dependencies)}개 의존성)")
                
                # 알려진 취약한 패키지
                vulnerable_packages = {
                    'express': {
                        'min_safe': '4.17.1',
                        'vuln': 'CVE-2019-5413, CVE-2019-5414'
                    },
                    'lodash': {
                        'min_safe': '4.17.21',
                        'vuln': 'CVE-2019-10744, CVE-2020-8203'
                    },
                    'moment': {
                        'min_safe': 'N/A',
                        'vuln': '유지보수 중단'
                    },
                    'jquery': {
                        'min_safe': '3.5.0',
                        'vuln': 'CVE-2020-11022, CVE-2020-11023'
                    },
                    'axios': {
                        'min_safe': '0.21.1',
                        'vuln': 'CVE-2020-28168'
                    },
                }
                
                for pkg, info in vulnerable_packages.items():
                    if pkg in dependencies:
                        version = dependencies[pkg].replace('^', '').replace('~', '').replace('>', '').replace('=', '')
                        details.append(f"    - {pkg}: {version}")
                        
                        if info['min_safe'] != 'N/A':
                            # 간단한 버전 비교
                            if version < info['min_safe']:
                                result['vulnerabilities'].append(f"취약한 {pkg}: {version}")
                                details.append(f"      ✗ 취약: {info['vuln']}")
                                result['status'] = 'VULNERABLE'
                        else:
                            result['vulnerabilities'].append(f"{pkg} 사용: {info['vuln']}")
                            details.append(f"      ⚠ {info['vuln']}")
                
            except json.JSONDecodeError:
                details.append("  • package.json 파싱 실패")
                
    except:
        pass
    
    # 5. composer.json 분석 (PHP)
    try:
        composer_resp = requests.get(f"{target_url}/composer.json", timeout=5)
        
        if composer_resp.status_code == 200:
            try:
                composer_data = json.loads(composer_resp.text)
                dependencies = composer_data.get('require', {})
                
                details.append(f"\n  발견: composer.json 노출 ({len(dependencies)}개 의존성)")
                
                # 알려진 취약한 PHP 패키지
                vulnerable_php = {
                    'laravel/framework': '오래된 Laravel',
                    'symfony/symfony': '오래된 Symfony',
                    'phpmailer/phpmailer': 'CVE-2016-10033',
                }
                
                for pkg in vulnerable_php.keys():
                    if pkg in dependencies:
                        version = dependencies[pkg]
                        details.append(f"    - {pkg}: {version}")
                
            except:
                pass
                
    except:
        pass
    
    # 6. WordPress/CMS 버전 탐지
    details.append("\n[컴포넌트-5] CMS 버전 확인")
    
    try:
        # WordPress
        wp_resp = requests.get(f"{target_url}/wp-includes/version.php", timeout=5)
        if wp_resp.status_code == 200:
            result['vulnerabilities'].append("WordPress 파일 노출")
            details.append("  ⚠ WordPress 사용 중 - 버전 확인 필요")
        
        # readme.html
        readme_resp = requests.get(f"{target_url}/readme.html", timeout=5)
        if readme_resp.status_code == 200:
            version_match = re.search(r'Version (\d+\.\d+)', readme_resp.text)
            if version_match:
                wp_version = version_match.group(1)
                details.append(f"  발견: WordPress {wp_version}")
                
                # WordPress 5.0 미만
                version_float = float(wp_version)
                if version_float < 5.0:
                    result['vulnerabilities'].append(f"오래된 WordPress: {wp_version}")
                    details.append(f"    ✗ WordPress {wp_version} - 알려진 취약점 다수")
                    result['status'] = 'VULNERABLE'
        
        # Joomla
        joomla_resp = requests.get(f"{target_url}/administrator/manifests/files/joomla.xml", timeout=5)
        if joomla_resp.status_code == 200:
            version_match = re.search(r'<version>(\d+\.\d+\.\d+)</version>', joomla_resp.text)
            if version_match:
                joomla_version = version_match.group(1)
                details.append(f"  발견: Joomla {joomla_version}")
        
        # Drupal
        drupal_resp = requests.get(f"{target_url}/CHANGELOG.txt", timeout=5)
        if drupal_resp.status_code == 200:
            version_match = re.search(r'Drupal (\d+\.\d+)', drupal_resp.text)
            if version_match:
                drupal_version = version_match.group(1)
                details.append(f"  발견: Drupal {drupal_version}")
                
    except:
        pass
    
    # 7. 프레임워크 탐지 (에러 페이지 기반)
    details.append("\n[컴포넌트-6] 프레임워크 정보 노출")
    
    try:
        # 존재하지 않는 페이지 요청
        error_resp = requests.get(f"{target_url}/nonexistent-page-12345", timeout=5)
        
        framework_indicators = {
            'Django': 'Django',
            'Flask': 'Flask',
            'Laravel': 'Laravel',
            'Spring': 'Spring Framework',
            'ASP.NET': 'ASP.NET',
            'Ruby on Rails': 'Rails',
            'Express': 'Express.js',
        }
        
        for indicator, framework_name in framework_indicators.items():
            if indicator in error_resp.text:
                details.append(f"  ⚠ {framework_name} 사용 중")
                
                # 버전 추출 시도
                version_match = re.search(rf'{indicator}[/\s]+(\d+\.\d+)', error_resp.text, re.IGNORECASE)
                if version_match:
                    version = version_match.group(1)
                    details.append(f"    버전: {version}")
                break
                
    except:
        pass
    
    # 8. CDN 사용 확인
    details.append("\n[컴포넌트-7] CDN 사용 확인")
    
    try:
        resp = requests.get(target_url, timeout=5)
        html = resp.text
        
        cdn_domains = [
            'cdn.jsdelivr.net',
            'unpkg.com',
            'cdnjs.cloudflare.com',
            'ajax.googleapis.com',
            'code.jquery.com',
            'stackpath.bootstrapcdn.com',
            'maxcdn.bootstrapcdn.com',
        ]
        
        used_cdns = []
        for cdn in cdn_domains:
            if cdn in html:
                used_cdns.append(cdn)
        
        if used_cdns:
            details.append(f"  사용 중인 CDN: {', '.join(used_cdns)}")
            details.append("  ⚠ CDN 리소스에 SRI 적용 확인 필요")
        
    except:
        pass
    
    result['details'] = '\n'.join(details)
    return result