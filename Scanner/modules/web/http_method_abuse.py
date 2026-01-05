"""
HTTP Method Abuse Scanner
HTTP 메서드 오용 및 취약점 탐지
"""
import requests

def scan(target_url):
    result = {
        'name': 'HTTP Method Abuse',
        'category': 'Configuration',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '불필요한 HTTP 메서드 비활성화, 메서드별 권한 검증',
        'details': ''
    }

    details = []

    # 테스트할 엔드포인트
    test_endpoints = [
        "/api/employees",
        "/api/boards",
        "/api/files",
        "/api/approvals",
    ]

    # 1. OPTIONS 메서드 확인
    details.append("[HTTP Method-1] OPTIONS 메서드")

    for endpoint in test_endpoints:
        try:
            url = f"{target_url}{endpoint}"
            resp = requests.options(url, timeout=5)

            if resp.status_code == 200:
                allowed_methods = resp.headers.get('Allow', '')
                details.append(f"  • {endpoint}: {allowed_methods}")

                # 위험한 메서드 확인
                dangerous_methods = ['TRACE', 'CONNECT', 'DELETE', 'PUT', 'PATCH']

                for method in dangerous_methods:
                    if method in allowed_methods:
                        result['vulnerabilities'].append(f"{method} 메서드 허용: {endpoint}")
                        details.append(f"     ⚠ {method} 메서드 노출됨")

        except:
            pass

    # 2. TRACE 메서드 (XST 취약점)
    details.append("\n[HTTP Method-2] TRACE 메서드 (XST)")

    for endpoint in test_endpoints:
        try:
            url = f"{target_url}{endpoint}"
            resp = requests.request('TRACE', url, timeout=5)

            if resp.status_code == 200:
                result['vulnerabilities'].append(f"TRACE 메서드 허용: {endpoint}")
                details.append(f"  ✗ {endpoint}: TRACE 허용 (XST 취약)")
                result['status'] = 'VULNERABLE'

                # 응답 본문에 요청 내용이 반사되는지 확인
                if 'TRACE' in resp.text:
                    details.append(f"     ⚠ 요청 내용 반사됨 (크로스사이트 트레이싱)")
                break

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ TRACE 메서드 차단됨")

    # 3. HEAD 메서드로 인증 우회
    details.append("\n[HTTP Method-3] HEAD 메서드 인증 우회")

    for endpoint in test_endpoints:
        try:
            url = f"{target_url}{endpoint}"

            # GET과 HEAD 비교
            get_resp = requests.get(url, timeout=5)
            head_resp = requests.head(url, timeout=5)

            # GET은 인증 필요하지만 HEAD는 허용되는지
            if get_resp.status_code == 401 and head_resp.status_code == 200:
                result['vulnerabilities'].append(f"HEAD 메서드로 인증 우회: {endpoint}")
                details.append(f"  ✗ {endpoint}: HEAD로 인증 우회 가능")
                result['status'] = 'VULNERABLE'

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ HEAD 메서드 인증 적용됨")

    # 4. HTTP Method Override
    details.append("\n[HTTP Method-4] HTTP Method Override")

    override_headers = [
        'X-HTTP-Method-Override',
        'X-HTTP-Method',
        'X-Method-Override',
    ]

    for endpoint in test_endpoints:
        try:
            url = f"{target_url}{endpoint}/1"

            # GET 요청이지만 DELETE로 오버라이드
            for header_name in override_headers:
                headers = {header_name: 'DELETE'}

                resp = requests.get(url, headers=headers, timeout=5)

                # 실제로 삭제되었는지 확인 (204 또는 200)
                if resp.status_code in [200, 204]:
                    result['vulnerabilities'].append(f"HTTP Method Override 허용: {header_name}")
                    details.append(f"  ✗ {header_name}로 메서드 오버라이드 가능")
                    result['status'] = 'VULNERABLE'
                    break

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ HTTP Method Override 차단됨")

    # 5. DELETE 메서드 접근 제어
    details.append("\n[HTTP Method-5] DELETE 메서드 접근 제어")

    for endpoint in test_endpoints:
        try:
            url = f"{target_url}{endpoint}/1"

            # 인증 없이 DELETE 시도
            resp = requests.delete(url, timeout=5)

            if resp.status_code in [200, 204]:
                result['vulnerabilities'].append(f"인증 없이 DELETE 가능: {endpoint}")
                details.append(f"  ✗ {endpoint}: 인증 없이 삭제 성공")
                result['status'] = 'VULNERABLE'
            elif resp.status_code == 401:
                details.append(f"  ✓ {endpoint}: DELETE 인증 필요 (401)")
            elif resp.status_code == 403:
                details.append(f"  ✓ {endpoint}: DELETE 권한 필요 (403)")
            elif resp.status_code == 405:
                details.append(f"  ✓ {endpoint}: DELETE 비활성화 (405)")

        except:
            pass

    # 6. PUT 메서드 접근 제어
    details.append("\n[HTTP Method-6] PUT 메서드 접근 제어")

    for endpoint in test_endpoints:
        try:
            url = f"{target_url}{endpoint}/1"

            # 인증 없이 PUT 시도
            update_data = {
                "name": "Hacked",
                "role": "ADMIN"
            }

            resp = requests.put(url, json=update_data, timeout=5)

            if resp.status_code in [200, 204]:
                result['vulnerabilities'].append(f"인증 없이 PUT 가능: {endpoint}")
                details.append(f"  ✗ {endpoint}: 인증 없이 수정 성공")
                result['status'] = 'VULNERABLE'
            elif resp.status_code == 401:
                details.append(f"  ✓ {endpoint}: PUT 인증 필요 (401)")
            elif resp.status_code == 403:
                details.append(f"  ✓ {endpoint}: PUT 권한 필요 (403)")

        except:
            pass

    # 7. CONNECT 메서드
    details.append("\n[HTTP Method-7] CONNECT 메서드")

    try:
        url = f"{target_url}/api/employees"
        resp = requests.request('CONNECT', url, timeout=5)

        if resp.status_code != 405:
            result['vulnerabilities'].append("CONNECT 메서드 허용")
            details.append(f"  ⚠ CONNECT 메서드 응답: {resp.status_code}")
        else:
            details.append(f"  ✓ CONNECT 메서드 차단됨")

    except:
        details.append(f"  • CONNECT 메서드 테스트 실패")

    # 8. PATCH vs PUT
    details.append("\n[HTTP Method-8] PATCH 메서드")

    for endpoint in test_endpoints:
        try:
            url = f"{target_url}{endpoint}/1"

            # PATCH로 부분 수정 시도
            patch_data = {"role": "ADMIN"}

            resp = requests.patch(url, json=patch_data, timeout=5)

            if resp.status_code in [200, 204]:
                details.append(f"  • {endpoint}: PATCH 허용됨")

                # 실제로 role이 변경되었는지 확인
                get_resp = requests.get(url, timeout=5)

                if get_resp.status_code == 200 and 'ADMIN' in get_resp.text:
                    result['vulnerabilities'].append(f"PATCH로 권한 변경: {endpoint}")
                    details.append(f"     ✗ PATCH로 role을 ADMIN으로 변경 성공")
                    result['status'] = 'VULNERABLE'

        except:
            pass

    # 9. POST to GET (메서드 혼동)
    details.append("\n[HTTP Method-9] 메서드 혼동")

    try:
        # GET 엔드포인트에 POST 시도
        url = f"{target_url}/api/employees/1"

        resp = requests.post(url, json={"test": "data"}, timeout=5)

        # POST가 GET처럼 동작하는지
        if resp.status_code == 200 and len(resp.text) > 100:
            result['vulnerabilities'].append("메서드 혼동 가능")
            details.append(f"  ⚠ POST 요청이 GET처럼 동작함")

    except:
        pass

    # 10. 대문자/소문자 메서드
    details.append("\n[HTTP Method-10] 대소문자 메서드")

    try:
        url = f"{target_url}/api/employees/1"

        case_variants = ['delete', 'Delete', 'DeLeTe', 'put', 'Put']

        for variant in case_variants:
            try:
                resp = requests.request(variant, url, timeout=3)

                if resp.status_code in [200, 204]:
                    result['vulnerabilities'].append(f"대소문자 메서드 허용: {variant}")
                    details.append(f"  ⚠ {variant} 메서드 허용됨")
                    break

            except:
                pass

    except:
        details.append(f"  • 대소문자 메서드 테스트 실패")

    if result['status'] == 'SAFE':
        details.append("\n✓ HTTP 메서드가 적절히 제어되고 있습니다")

    result['details'] = '\n'.join(details)
    return result
