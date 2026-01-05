"""
Information Disclosure Scanner
에러 메시지, 서버 정보, 디버그 정보 노출 탐지
"""
import requests
import re

def scan(target_url):
    result = {
        'name': 'Information Disclosure',
        'category': 'Information Leakage',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '에러 메시지 일반화, 디버그 모드 비활성화, 서버 정보 숨김',
        'details': ''
    }

    details = []

    # 1. 에러 메시지 유도 테스트
    details.append("[정보 노출 테스트 - 에러 메시지]")

    error_tests = [
        ("/api/employees/99999", "존재하지 않는 직원 ID"),
        ("/api/boards/99999", "존재하지 않는 게시글 ID"),
        ("/api/files/99999", "존재하지 않는 파일 ID"),
        ("/api/approvals/99999", "존재하지 않는 결재 ID"),
        ("/api/../../../etc/passwd", "경로 순회 시도"),
        ("/api/employees/' OR '1'='1", "SQL Injection 시도"),
    ]

    sensitive_patterns = {
        'Stack Trace': [
            r'at\s+[\w\.$]+\(',  # Java stack trace
            r'Traceback\s+\(most recent call last\)',  # Python traceback
            r'Exception in thread',
            r'\.java:\d+',
            r'\.py:\d+',
            r'org\.springframework',
            r'java\.lang\.',
            r'javax\.servlet',
        ],
        'Database Info': [
            r'SQL syntax',
            r'mysql',
            r'postgresql',
            r'ORA-\d+',
            r'SQLException',
            r'database error',
            r'DB2 SQL error',
        ],
        'Framework Info': [
            r'Spring Framework',
            r'Hibernate',
            r'Django',
            r'Flask',
            r'Express',
            r'Laravel',
        ],
        'File Paths': [
            r'[A-Z]:\\[\w\\]+',  # Windows path
            r'/var/www/',
            r'/home/[\w/]+',
            r'/usr/[\w/]+',
            r'C:\\Users\\',
        ],
        'Debug Info': [
            r'DEBUG',
            r'TRACE',
            r'<pre>',
            r'var_dump',
            r'print_r',
            r'console\.log',
        ]
    }

    for endpoint, description in error_tests:
        try:
            url = f"{target_url}{endpoint}"
            resp = requests.get(url, timeout=5)

            # HTTP 에러 코드 확인
            if resp.status_code >= 400:
                details.append(f"  • {description}: {resp.status_code}")

                # 응답 내용에서 민감 정보 탐지
                for category, patterns in sensitive_patterns.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, resp.text, re.IGNORECASE)
                        if matches:
                            vuln_msg = f"{category} 노출 - {description}"
                            if vuln_msg not in result['vulnerabilities']:
                                result['vulnerabilities'].append(vuln_msg)
                                details.append(f"     ✗ {category} 발견: {matches[0][:50]}...")
                                result['status'] = 'VULNERABLE'
                            break

        except:
            pass

    # 2. 서버 정보 노출
    details.append("\n[서버 정보 노출]")

    try:
        resp = requests.get(target_url, timeout=5)
        headers = resp.headers

        # Server 헤더
        if 'Server' in headers:
            server_info = headers['Server']
            result['vulnerabilities'].append(f"Server 헤더 노출: {server_info}")
            details.append(f"  ✗ Server: {server_info}")
            result['status'] = 'VULNERABLE'

            # 버전 정보 확인
            version_pattern = r'\d+\.\d+(\.\d+)?'
            if re.search(version_pattern, server_info):
                result['vulnerabilities'].append("서버 버전 정보 노출")
                details.append(f"     ⚠ 버전 정보 노출")
        else:
            details.append(f"  ✓ Server 헤더 숨김")

        # X-Powered-By 헤더
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            result['vulnerabilities'].append(f"X-Powered-By 헤더 노출: {powered_by}")
            details.append(f"  ✗ X-Powered-By: {powered_by}")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ X-Powered-By 헤더 숨김")

        # X-AspNet-Version
        if 'X-AspNet-Version' in headers:
            aspnet_version = headers['X-AspNet-Version']
            result['vulnerabilities'].append(f"ASP.NET 버전 노출: {aspnet_version}")
            details.append(f"  ✗ X-AspNet-Version: {aspnet_version}")
            result['status'] = 'VULNERABLE'

        # X-AspNetMvc-Version
        if 'X-AspNetMvc-Version' in headers:
            mvc_version = headers['X-AspNetMvc-Version']
            result['vulnerabilities'].append(f"ASP.NET MVC 버전 노출: {mvc_version}")
            details.append(f"  ✗ X-AspNetMvc-Version: {mvc_version}")
            result['status'] = 'VULNERABLE'

    except:
        details.append("  • 서버 정보 확인 실패")

    # 3. 디버그 정보 노출
    details.append("\n[디버그 정보 노출]")

    debug_endpoints = [
        "/debug",
        "/trace",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/mappings",
        "/swagger-ui.html",
        "/api-docs",
        "/graphql",
        "/.env",
        "/config",
    ]

    for endpoint in debug_endpoints:
        try:
            url = f"{target_url}{endpoint}"
            resp = requests.get(url, timeout=3)

            if resp.status_code == 200:
                result['vulnerabilities'].append(f"디버그 엔드포인트 노출: {endpoint}")
                details.append(f"  ✗ {endpoint}: 접근 가능 ({resp.status_code})")
                result['status'] = 'VULNERABLE'

                # 민감 정보 확인
                if 'password' in resp.text.lower() or 'secret' in resp.text.lower():
                    result['vulnerabilities'].append(f"민감 정보 포함: {endpoint}")
                    details.append(f"     ⚠ 민감 정보(password/secret) 포함")

        except:
            pass

    # 4. 주석에 민감 정보 포함
    details.append("\n[HTML/JS 주석 확인]")

    try:
        resp = requests.get(target_url, timeout=5)
        html_content = resp.text

        # HTML 주석 찾기
        html_comments = re.findall(r'<!--(.*?)-->', html_content, re.DOTALL)
        if html_comments:
            details.append(f"  • HTML 주석 발견: {len(html_comments)}개")

            sensitive_keywords = ['password', 'secret', 'api_key', 'token', 'admin', 'todo', 'fixme', 'hack', 'bug']
            for comment in html_comments:
                for keyword in sensitive_keywords:
                    if keyword in comment.lower():
                        result['vulnerabilities'].append(f"주석에 민감 키워드: {keyword}")
                        details.append(f"     ✗ 민감 키워드 '{keyword}' 발견")
                        result['status'] = 'VULNERABLE'
                        break

        # JavaScript 주석 찾기
        js_comments = re.findall(r'//(.*?)$|/\*(.*?)\*/', html_content, re.MULTILINE | re.DOTALL)
        if js_comments:
            details.append(f"  • JS 주석 발견: {len(js_comments)}개")

    except:
        details.append("  • 주석 확인 실패")

    # 5. API 응답 정보 노출
    details.append("\n[API 응답 정보]")

    try:
        # 인증 없이 API 호출
        api_endpoints = [
            "/api/employees",
            "/api/boards",
            "/api/departments",
            "/api/teams",
        ]

        for endpoint in api_endpoints:
            try:
                url = f"{target_url}{endpoint}"
                resp = requests.get(url, timeout=3)

                if resp.status_code == 200:
                    # JSON 응답에 불필요한 정보 포함 여부
                    if 'password' in resp.text.lower():
                        result['vulnerabilities'].append(f"API 응답에 password 필드: {endpoint}")
                        details.append(f"  ✗ {endpoint}: password 필드 포함")
                        result['status'] = 'VULNERABLE'

                    if 'ssn' in resp.text.lower() or 'social_security' in resp.text.lower():
                        result['vulnerabilities'].append(f"API 응답에 주민번호: {endpoint}")
                        details.append(f"  ✗ {endpoint}: 주민번호 필드 포함")
                        result['status'] = 'VULNERABLE'

            except:
                pass

    except:
        details.append("  • API 응답 확인 실패")

    # 6. 디렉토리 리스팅
    details.append("\n[디렉토리 리스팅]")

    directory_paths = [
        "/uploads/",
        "/files/",
        "/static/",
        "/assets/",
        "/images/",
        "/docs/",
    ]

    for path in directory_paths:
        try:
            url = f"{target_url}{path}"
            resp = requests.get(url, timeout=3)

            if resp.status_code == 200:
                # 디렉토리 리스팅 패턴 확인
                if 'Index of' in resp.text or 'Directory listing' in resp.text:
                    result['vulnerabilities'].append(f"디렉토리 리스팅 허용: {path}")
                    details.append(f"  ✗ {path}: 디렉토리 리스팅 가능")
                    result['status'] = 'VULNERABLE'

        except:
            pass

    if result['status'] == 'SAFE':
        details.append("\n✓ 정보 노출이 적절히 차단되어 있습니다")

    result['details'] = '\n'.join(details)
    return result
