"""
HTTP Parameter Pollution Scanner
파라미터 중복 및 오용 취약점 탐지
"""
import requests

def scan(target_url):
    result = {
        'name': 'HTTP Parameter Pollution (HPP)',
        'category': 'Injection',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '파라미터 중복 검증, 명확한 파라미터 파싱 정책',
        'details': ''
    }

    details = []

    # 1. 중복 파라미터 처리 방식
    details.append("[HPP-1] 중복 파라미터 처리")

    test_endpoints = [
        "/api/boards",
        "/api/employees",
        "/api/approvals",
    ]

    for endpoint in test_endpoints:
        try:
            url = f"{target_url}{endpoint}"

            # 동일 파라미터를 여러 번 전송
            # ?search=value1&search=value2
            params_list = [
                ('search', 'value1'),
                ('search', 'value2'),
            ]

            resp = requests.get(url, params=params_list, timeout=5)

            if resp.status_code == 200:
                # 어떤 값이 사용되었는지 확인
                if 'value1' in resp.text and 'value2' in resp.text:
                    details.append(f"  • {endpoint}: 중복 파라미터 모두 처리됨")
                elif 'value1' in resp.text:
                    details.append(f"  • {endpoint}: 첫 번째 값 사용")
                elif 'value2' in resp.text:
                    details.append(f"  • {endpoint}: 마지막 값 사용")
                else:
                    details.append(f"  • {endpoint}: 중복 파라미터 무시됨")

        except:
            pass

    # 2. 배열 파라미터 조작
    details.append("\n[HPP-2] 배열 파라미터")

    try:
        url = f"{target_url}/api/employees"

        # 배열 형태 파라미터
        test_cases = [
            {"id[]": ["1", "2", "3"]},  # PHP 스타일
            {"id": ["1", "2", "3"]},     # 일반 배열
        ]

        for params in test_cases:
            resp = requests.get(url, params=params, timeout=5)

            if resp.status_code == 200:
                # 여러 ID가 모두 조회되었는지
                if '1' in resp.text and '2' in resp.text and '3' in resp.text:
                    details.append(f"  • 배열 파라미터 처리됨")
                    break

    except:
        details.append(f"  • 배열 파라미터 테스트 실패")

    # 3. 필터 우회
    details.append("\n[HPP-3] 필터 우회")

    try:
        url = f"{target_url}/api/boards"

        # 첫 번째 파라미터는 필터링하지만 두 번째는 필터링 안 할 수 있음
        # ?search=safe&search=<script>alert(1)</script>
        params_list = [
            ('search', 'safe'),
            ('search', '<script>alert(1)</script>'),
        ]

        resp = requests.get(url, params=params_list, timeout=5)

        if resp.status_code == 200:
            if '<script>' in resp.text or 'alert(1)' in resp.text:
                result['vulnerabilities'].append("중복 파라미터로 필터 우회")
                details.append(f"  ✗ 두 번째 파라미터로 XSS 필터 우회")
                result['status'] = 'VULNERABLE'
            else:
                details.append(f"  ✓ 중복 파라미터 필터링됨")

    except:
        details.append(f"  • 필터 우회 테스트 실패")

    # 4. 인증 우회
    details.append("\n[HPP-4] 인증 우회")

    try:
        url = f"{target_url}/api/employees/1"

        # employeeId 파라미터 중복
        # ?employeeId=attacker&employeeId=victim
        params_list = [
            ('employeeId', '999'),  # 공격자 ID
            ('employeeId', '1'),    # 피해자 ID
        ]

        resp = requests.get(url, params=params_list, timeout=5)

        if resp.status_code == 200 and len(resp.text) > 100:
            # 데이터가 조회되었다면
            result['vulnerabilities'].append("중복 파라미터로 인증 우회 가능")
            details.append(f"  ✗ 중복 employeeId로 데이터 조회 성공")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ 중복 파라미터 인증 검증됨")

    except:
        details.append(f"  • 인증 우회 테스트 실패")

    # 5. SQL Injection 우회
    details.append("\n[HPP-5] SQL Injection 우회")

    try:
        url = f"{target_url}/api/boards"

        # 첫 번째는 안전, 두 번째는 SQL Injection
        params_list = [
            ('search', 'test'),
            ('search', "' OR '1'='1"),
        ]

        resp = requests.get(url, params=params_list, timeout=5)

        if resp.status_code == 200:
            # 모든 데이터가 조회되었는지 (SQL Injection 성공)
            if 'SQL' in resp.text or len(resp.text) > 5000:
                result['vulnerabilities'].append("중복 파라미터로 SQL Injection")
                details.append(f"  ✗ 두 번째 파라미터로 SQL Injection 가능")
                result['status'] = 'VULNERABLE'
            else:
                details.append(f"  ✓ SQL Injection 차단됨")

    except:
        details.append(f"  • SQL Injection 테스트 실패")

    # 6. 권한 상승
    details.append("\n[HPP-6] 권한 상승")

    try:
        url = f"{target_url}/api/employees"

        # role 파라미터 중복
        params_list = [
            ('role', 'USER'),
            ('role', 'ADMIN'),
        ]

        resp = requests.get(url, params=params_list, timeout=5)

        if resp.status_code == 200:
            if 'ADMIN' in resp.text:
                result['vulnerabilities'].append("중복 파라미터로 권한 상승")
                details.append(f"  ✗ role 파라미터 중복으로 ADMIN 권한 획득")
                result['status'] = 'VULNERABLE'

    except:
        details.append(f"  • 권한 상승 테스트 실패")

    # 7. POST 파라미터 오염
    details.append("\n[HPP-7] POST Body 파라미터 중복")

    try:
        url = f"{target_url}/api/auth/login"

        # application/x-www-form-urlencoded
        # employeeId=user1&employeeId=admin
        data = "employeeId=test_user&password=wrong&employeeId=admin"

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        resp = requests.post(url, data=data, headers=headers, timeout=5)

        if resp.status_code == 200:
            # admin으로 로그인되었는지 확인
            try:
                response_data = resp.json()
                if 'admin' in str(response_data).lower():
                    result['vulnerabilities'].append("POST 파라미터 오염")
                    details.append(f"  ✗ 중복 employeeId로 다른 계정 로그인")
                    result['status'] = 'VULNERABLE'
            except:
                pass

    except:
        details.append(f"  • POST 파라미터 테스트 실패")

    # 8. Query vs Body 파라미터 우선순위
    details.append("\n[HPP-8] Query vs Body 우선순위")

    try:
        url = f"{target_url}/api/boards"

        # URL 쿼리와 Body에 동일 파라미터
        params = {'search': 'query_value'}
        data = {'search': 'body_value'}

        resp = requests.post(url, params=params, json=data, timeout=5)

        if resp.status_code in [200, 201]:
            if 'query_value' in resp.text:
                details.append(f"  • Query 파라미터 우선")
            elif 'body_value' in resp.text:
                details.append(f"  • Body 파라미터 우선")

    except:
        details.append(f"  • Query vs Body 테스트 실패")

    # 9. 파라미터 이름 대소문자
    details.append("\n[HPP-9] 파라미터 대소문자")

    try:
        url = f"{target_url}/api/boards"

        # search, Search, SEARCH
        params_list = [
            ('search', 'lowercase'),
            ('Search', 'capitalized'),
            ('SEARCH', 'uppercase'),
        ]

        resp = requests.get(url, params=params_list, timeout=5)

        if resp.status_code == 200:
            found = []
            if 'lowercase' in resp.text:
                found.append('search')
            if 'capitalized' in resp.text:
                found.append('Search')
            if 'uppercase' in resp.text:
                found.append('SEARCH')

            if len(found) > 1:
                details.append(f"  • 대소문자 구분 안 됨: {', '.join(found)}")
            else:
                details.append(f"  ✓ 대소문자 구분됨")

    except:
        details.append(f"  • 대소문자 테스트 실패")

    # 10. JSON vs Form 파라미터 충돌
    details.append("\n[HPP-10] JSON vs Form 충돌")

    try:
        url = f"{target_url}/api/boards"

        # JSON Content-Type이지만 Form 데이터 전송
        data = "title=Form Title&content=Form Content"
        headers = {
            'Content-Type': 'application/json'
        }

        resp = requests.post(url, data=data, headers=headers, timeout=5)

        if resp.status_code in [200, 201]:
            result['vulnerabilities'].append("Content-Type 불일치 허용")
            details.append(f"  ⚠ JSON Content-Type이지만 Form 데이터 처리됨")

    except:
        details.append(f"  • JSON vs Form 테스트 실패")

    if result['status'] == 'SAFE':
        details.append("\n✓ HTTP Parameter Pollution 방어가 적절합니다")

    result['details'] = '\n'.join(details)
    return result
