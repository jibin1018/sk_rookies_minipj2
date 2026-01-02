"""
Host Header Injection Scanner
Host 헤더 조작 취약점 탐지
"""
import requests

def scan(target_url):
    result = {
        'name': 'Host Header Injection',
        'category': 'Injection',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'Host 헤더 검증, 허용된 도메인 화이트리스트, 절대 URL 사용',
        'details': ''
    }

    details = []

    # 1. Host 헤더 변조
    details.append("[Host Header-1] Host 헤더 변조")

    malicious_hosts = [
        "evil.com",
        "attacker.com",
        "127.0.0.1",
        "localhost:8080",
    ]

    for evil_host in malicious_hosts:
        try:
            headers = {"Host": evil_host}
            resp = requests.get(target_url, headers=headers, timeout=5)

            # 응답에 악의적인 Host가 반영되었는지 확인
            if evil_host in resp.text:
                result['vulnerabilities'].append(f"Host 헤더 반영: {evil_host}")
                details.append(f"  ✗ Host 헤더가 응답에 반영됨: {evil_host}")
                result['status'] = 'VULNERABLE'

                # 링크나 리다이렉트에 포함되었는지
                if '<a href' in resp.text or 'window.location' in resp.text:
                    details.append(f"     ⚠ 링크/리다이렉트에 포함됨")
                break

        except:
            pass

    if result['status'] == 'SAFE':
        details.append("  ✓ Host 헤더 변조 차단됨")

    # 2. 비밀번호 재설정 링크 조작
    details.append("\n[Host Header-2] 비밀번호 재설정 링크")

    password_reset_endpoints = [
        "/api/auth/reset-password",
        "/api/auth/forgot-password",
        "/api/password/reset",
    ]

    for endpoint in password_reset_endpoints:
        try:
            url = f"{target_url}{endpoint}"

            # Host 헤더를 악의적인 도메인으로 변경
            headers = {"Host": "evil.com"}
            data = {"email": "test@example.com"}

            resp = requests.post(url, headers=headers, json=data, timeout=5)

            # 응답 확인
            if resp.status_code in [200, 201, 204]:
                # 이메일이 발송되었다고 가정하고, 악의적인 Host가 포함될 수 있음
                result['vulnerabilities'].append("비밀번호 재설정 링크 조작 가능")
                details.append(f"  ✗ {endpoint}: Host 헤더로 재설정 링크 조작 가능")
                result['status'] = 'VULNERABLE'
                break

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ 비밀번호 재설정 링크 안전")

    # 3. X-Forwarded-Host 헤더
    details.append("\n[Host Header-3] X-Forwarded-Host")

    try:
        headers = {
            "X-Forwarded-Host": "evil.com",
            "X-Forwarded-For": "1.2.3.4"
        }

        resp = requests.get(target_url, headers=headers, timeout=5)

        if "evil.com" in resp.text:
            result['vulnerabilities'].append("X-Forwarded-Host 반영됨")
            details.append(f"  ✗ X-Forwarded-Host가 응답에 반영됨")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ X-Forwarded-Host 무시됨")

    except:
        details.append(f"  • X-Forwarded-Host 테스트 실패")

    # 4. 중복 Host 헤더
    details.append("\n[Host Header-4] 중복 Host 헤더")

    try:
        # 중복 Host 헤더 전송
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        # 수동 HTTP 요청 구성
        request_data = f"GET / HTTP/1.1\r\n"
        request_data += f"Host: {host}\r\n"
        request_data += f"Host: evil.com\r\n"
        request_data += f"Connection: close\r\n\r\n"

        # 소켓 연결 (테스트 목적)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.send(request_data.encode())

            response = sock.recv(4096).decode()
            sock.close()

            if "evil.com" in response:
                result['vulnerabilities'].append("중복 Host 헤더 허용")
                details.append(f"  ✗ 중복 Host 헤더 처리 취약")
                result['status'] = 'VULNERABLE'
            else:
                details.append(f"  ✓ 중복 Host 헤더 차단됨")

        except:
            details.append(f"  • 중복 Host 헤더 테스트 실패 (소켓 연결)")

    except:
        details.append(f"  • 중복 Host 헤더 테스트 실패")

    # 5. Host 헤더로 캐시 포이즈닝
    details.append("\n[Host Header-5] 캐시 포이즈닝 가능성")

    try:
        # 정적 리소스에 Host 헤더 변조
        static_urls = [
            f"{target_url}/static/css/style.css",
            f"{target_url}/static/js/app.js",
            f"{target_url}/favicon.ico",
        ]

        for static_url in static_urls:
            try:
                headers = {"Host": "evil.com"}
                resp = requests.get(static_url, headers=headers, timeout=5)

                # 응답에 Host가 포함되어 있으면 캐시 포이즈닝 가능
                if resp.status_code == 200 and "evil.com" in resp.text:
                    result['vulnerabilities'].append("정적 리소스 Host 헤더 반영")
                    details.append(f"  ⚠ 정적 리소스에 Host 반영 (캐시 포이즈닝 가능)")
                    break

            except:
                pass

    except:
        details.append(f"  • 캐시 포이즈닝 테스트 실패")

    # 6. Host 헤더로 SQL Injection
    details.append("\n[Host Header-6] Host 헤더 SQL Injection")

    sql_payloads = [
        "evil.com' OR '1'='1",
        "evil.com'; DROP TABLE users--",
        "evil.com' UNION SELECT NULL--",
    ]

    for payload in sql_payloads:
        try:
            headers = {"Host": payload}
            resp = requests.get(target_url, headers=headers, timeout=5)

            # SQL 에러 메시지 확인
            sql_errors = ['SQL syntax', 'mysql', 'PostgreSQL', 'ORA-', 'syntax error']

            for error in sql_errors:
                if error in resp.text:
                    result['vulnerabilities'].append("Host 헤더로 SQL Injection")
                    details.append(f"  ✗ Host 헤더가 SQL 쿼리에 사용됨")
                    result['status'] = 'VULNERABLE'
                    break

            if result['status'] == 'VULNERABLE':
                break

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ Host 헤더 SQL Injection 없음")

    # 7. Absolute URL 생성
    details.append("\n[Host Header-7] Absolute URL 생성")

    try:
        headers = {"Host": "evil.com"}
        resp = requests.get(f"{target_url}/api/boards", headers=headers, timeout=5)

        # 절대 URL이 생성되었는지 확인
        if "http://evil.com" in resp.text or "https://evil.com" in resp.text:
            result['vulnerabilities'].append("Host 헤더로 절대 URL 생성")
            details.append(f"  ✗ Host 헤더 기반 절대 URL 생성됨")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ 절대 URL이 Host 헤더 영향 받지 않음")

    except:
        details.append(f"  • Absolute URL 테스트 실패")

    # 8. Port 조작
    details.append("\n[Host Header-8] Port 조작")

    try:
        headers = {"Host": "localhost:22"}  # SSH 포트
        resp = requests.get(target_url, headers=headers, timeout=5)

        if ":22" in resp.text:
            result['vulnerabilities'].append("Host 헤더 Port 조작")
            details.append(f"  ⚠ Port가 응답에 반영됨")

    except:
        details.append(f"  • Port 조작 테스트 실패")

    # 9. SSRF via Host Header
    details.append("\n[Host Header-9] SSRF via Host Header")

    ssrf_payloads = [
        "127.0.0.1",
        "localhost",
        "169.254.169.254",  # AWS 메타데이터
        "metadata.google.internal",  # GCP 메타데이터
    ]

    for payload in ssrf_payloads:
        try:
            headers = {"Host": payload}
            resp = requests.get(target_url, headers=headers, timeout=5)

            # 내부 IP로 요청이 갔는지 확인
            if payload in resp.text or "metadata" in resp.text:
                result['vulnerabilities'].append(f"Host 헤더로 SSRF: {payload}")
                details.append(f"  ✗ Host 헤더로 내부 리소스 접근 가능")
                result['status'] = 'VULNERABLE'
                break

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ Host 헤더 SSRF 차단됨")

    # 10. Referer vs Host
    details.append("\n[Host Header-10] Referer와 Host 불일치")

    try:
        headers = {
            "Host": "evil.com",
            "Referer": "http://legitimate.com"
        }

        resp = requests.get(target_url, headers=headers, timeout=5)

        # Host와 Referer가 다를 때 처리
        if resp.status_code == 200:
            details.append(f"  • Host와 Referer 불일치 허용")

    except:
        pass

    if result['status'] == 'SAFE':
        details.append("\n✓ Host 헤더가 적절히 검증되고 있습니다")

    result['details'] = '\n'.join(details)
    return result
