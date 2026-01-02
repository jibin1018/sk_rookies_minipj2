"""
Open Redirect Scanner
오픈 리다이렉트 취약점 탐지
"""
import requests

def scan(target_url):
    result = {
        'name': 'Open Redirect',
        'category': 'Redirection',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '리다이렉트 URL 화이트리스트, 내부 URL만 허용, 사용자 확인',
        'details': ''
    }

    details = []

    # 1. 로그인 후 리다이렉트
    details.append("[Open Redirect-1] 로그인 리다이렉트")

    login_url = f"{target_url}/api/auth/login"

    redirect_payloads = [
        "http://evil.com",
        "https://attacker.com/phishing",
        "//evil.com",
        "///evil.com",
        "http:///evil.com",
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
    ]

    for payload in redirect_payloads:
        try:
            # redirect 또는 returnUrl 파라미터
            params = {"redirect": payload}

            resp = requests.get(login_url, params=params, timeout=5, allow_redirects=False)

            # 30x 리다이렉트 응답 확인
            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get('Location', '')

                if payload in location or 'evil.com' in location:
                    result['vulnerabilities'].append(f"Open Redirect: {payload}")
                    details.append(f"  ✗ 외부 URL로 리다이렉트: {payload}")
                    result['status'] = 'VULNERABLE'
                    break

        except:
            pass

    if result['status'] == 'SAFE':
        details.append("  ✓ 로그인 리다이렉트 검증됨")

    # 2. returnUrl 파라미터
    details.append("\n[Open Redirect-2] returnUrl 파라미터")

    return_url_endpoints = [
        "/api/auth/login",
        "/api/auth/logout",
        "/login",
        "/logout",
    ]

    for endpoint in return_url_endpoints:
        for payload in redirect_payloads:
            try:
                url = f"{target_url}{endpoint}"
                params = {"returnUrl": payload, "return": payload, "next": payload}

                resp = requests.get(url, params=params, timeout=5, allow_redirects=False)

                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get('Location', '')

                    if 'evil.com' in location or payload in location:
                        result['vulnerabilities'].append(f"returnUrl 조작 가능: {endpoint}")
                        details.append(f"  ✗ {endpoint}: 외부 리다이렉트 허용")
                        result['status'] = 'VULNERABLE'
                        break

            except:
                pass

        if result['status'] == 'VULNERABLE':
            break

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ returnUrl 파라미터 검증됨")

    # 3. 프로토콜 우회
    details.append("\n[Open Redirect-3] 프로토콜 우회")

    protocol_bypass_payloads = [
        "//evil.com",  # 프로토콜 생략
        "///evil.com",
        "////evil.com",
        "http:///evil.com",
        "https:///evil.com",
        "HtTp://evil.com",  # 대소문자
        "//google.com%2f@evil.com",
        "https://evil.com%00.example.com",  # Null byte
    ]

    for payload in protocol_bypass_payloads:
        try:
            url = f"{target_url}/api/auth/login"
            params = {"redirect": payload}

            resp = requests.get(url, params=params, timeout=5, allow_redirects=False)

            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get('Location', '')

                if 'evil.com' in location or 'google.com' in location:
                    result['vulnerabilities'].append(f"프로토콜 우회: {payload}")
                    details.append(f"  ✗ 프로토콜 우회 성공: {payload}")
                    result['status'] = 'VULNERABLE'
                    break

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ 프로토콜 우회 차단됨")

    # 4. @를 이용한 우회
    details.append("\n[Open Redirect-4] @ 문자 우회")

    at_bypass_payloads = [
        "http://example.com@evil.com",
        "http://example.com%40evil.com",
        "http://example.com:80@evil.com",
        "http://user@evil.com:80@example.com",
    ]

    for payload in at_bypass_payloads:
        try:
            url = f"{target_url}/api/auth/login"
            params = {"redirect": payload}

            resp = requests.get(url, params=params, timeout=5, allow_redirects=False)

            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get('Location', '')

                if 'evil.com' in location:
                    result['vulnerabilities'].append(f"@ 문자 우회: {payload}")
                    details.append(f"  ✗ @ 문자로 검증 우회")
                    result['status'] = 'VULNERABLE'
                    break

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ @ 문자 우회 차단됨")

    # 5. 백슬래시 우회
    details.append("\n[Open Redirect-5] 백슬래시 우회")

    backslash_payloads = [
        "http://example.com\\evil.com",
        "http:\\\\evil.com",
        "http://example.com\\\\evil.com",
    ]

    for payload in backslash_payloads:
        try:
            url = f"{target_url}/api/auth/login"
            params = {"redirect": payload}

            resp = requests.get(url, params=params, timeout=5, allow_redirects=False)

            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get('Location', '')

                if 'evil.com' in location:
                    result['vulnerabilities'].append("백슬래시 우회")
                    details.append(f"  ✗ 백슬래시로 검증 우회")
                    result['status'] = 'VULNERABLE'
                    break

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ 백슬래시 우회 차단됨")

    # 6. 상대 경로 우회
    details.append("\n[Open Redirect-6] 상대 경로 조작")

    relative_payloads = [
        "../../evil.com",
        "/../..//../../evil.com",
        "./../.../../evil.com",
    ]

    for payload in relative_payloads:
        try:
            url = f"{target_url}/api/auth/login"
            params = {"redirect": payload}

            resp = requests.get(url, params=params, timeout=5, allow_redirects=False)

            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get('Location', '')

                if 'evil.com' in location:
                    result['vulnerabilities'].append("상대 경로 우회")
                    details.append(f"  ✗ 상대 경로로 외부 리다이렉트")
                    result['status'] = 'VULNERABLE'
                    break

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ 상대 경로 조작 차단됨")

    # 7. 인코딩 우회
    details.append("\n[Open Redirect-7] URL 인코딩 우회")

    encoded_payloads = [
        "http%3A%2F%2Fevil.com",  # URL 인코딩
        "%68%74%74%70%3A%2F%2Fevil.com",  # 완전 인코딩
        "http://evil%2ecom",
    ]

    for payload in encoded_payloads:
        try:
            url = f"{target_url}/api/auth/login"
            params = {"redirect": payload}

            resp = requests.get(url, params=params, timeout=5, allow_redirects=False)

            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get('Location', '')

                if 'evil.com' in location or 'evil%' in location:
                    result['vulnerabilities'].append("URL 인코딩 우회")
                    details.append(f"  ✗ URL 인코딩으로 검증 우회")
                    result['status'] = 'VULNERABLE'
                    break

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ URL 인코딩 우회 차단됨")

    # 8. 도메인 유사성 우회
    details.append("\n[Open Redirect-8] 도메인 유사성")

    similar_domain_payloads = [
        f"{target_url.replace('http://', '').replace('https://', '')}.evil.com",
        f"{target_url}-evil.com",
    ]

    for payload in similar_domain_payloads:
        try:
            url = f"{target_url}/api/auth/login"
            params = {"redirect": f"http://{payload}"}

            resp = requests.get(url, params=params, timeout=5, allow_redirects=False)

            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get('Location', '')

                if 'evil.com' in location:
                    result['vulnerabilities'].append("도메인 유사성 우회")
                    details.append(f"  ✗ 유사 도메인으로 검증 우회")
                    result['status'] = 'VULNERABLE'
                    break

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ 도메인 유사성 차단됨")

    # 9. Meta Refresh 태그
    details.append("\n[Open Redirect-9] Meta Refresh")

    try:
        url = f"{target_url}/api/auth/login"
        params = {"redirect": "http://evil.com"}

        resp = requests.get(url, params=params, timeout=5)

        # Meta refresh 태그 확인
        if '<meta' in resp.text.lower() and 'refresh' in resp.text.lower() and 'evil.com' in resp.text:
            result['vulnerabilities'].append("Meta Refresh 리다이렉트")
            details.append(f"  ✗ Meta Refresh 태그로 리다이렉트")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ Meta Refresh 없음")

    except:
        details.append(f"  • Meta Refresh 확인 실패")

    # 10. JavaScript 리다이렉트
    details.append("\n[Open Redirect-10] JavaScript 리다이렉트")

    try:
        url = f"{target_url}/api/auth/login"
        params = {"redirect": "http://evil.com"}

        resp = requests.get(url, params=params, timeout=5)

        # window.location 또는 location.href 확인
        js_patterns = ['window.location', 'location.href', 'location.replace']

        for pattern in js_patterns:
            if pattern in resp.text and 'evil.com' in resp.text:
                result['vulnerabilities'].append("JavaScript 리다이렉트")
                details.append(f"  ✗ JS로 외부 URL 리다이렉트: {pattern}")
                result['status'] = 'VULNERABLE'
                break

    except:
        details.append(f"  • JavaScript 확인 실패")

    if result['status'] == 'SAFE':
        details.append("\n✓ Open Redirect 방어가 적절히 구현되어 있습니다")

    result['details'] = '\n'.join(details)
    return result
