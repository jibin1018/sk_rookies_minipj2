"""
IDOR (Insecure Direct Object Reference) Scanner
객체 참조 취약점 - 권한 없이 타인의 데이터 접근 가능 여부 탐지
"""
import requests

def scan(target_url):
    result = {
        'name': 'IDOR (Insecure Direct Object Reference)',
        'category': 'Access Control',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': '모든 객체 접근 시 권한 검증, UUID 사용, 간접 참조 맵 사용',
        'details': ''
    }

    details = []

    # 1. 순차적 ID 예측 가능성
    details.append("[IDOR-1] 순차적 ID 예측 테스트")

    # 테스트할 엔드포인트
    id_based_endpoints = [
        ("/api/employees/{id}", "직원 정보"),
        ("/api/boards/{id}", "게시글"),
        ("/api/files/{id}", "파일"),
        ("/api/approvals/{id}", "결재"),
        ("/api/teams/{id}", "팀"),
        ("/api/departments/{id}", "부서"),
    ]

    sequential_ids_found = False

    for endpoint_pattern, resource_name in id_based_endpoints:
        try:
            # ID 1, 2, 3으로 연속 테스트
            ids_to_test = [1, 2, 3, 100, 999]
            accessible_ids = []

            for test_id in ids_to_test:
                url = f"{target_url}{endpoint_pattern.format(id=test_id)}"

                try:
                    resp = requests.get(url, timeout=3)

                    if resp.status_code == 200:
                        accessible_ids.append(test_id)
                except:
                    pass

            # 연속된 ID 3개 이상 접근 가능하면 취약
            if len(accessible_ids) >= 3:
                sequential_ids_found = True
                result['vulnerabilities'].append(f"순차적 ID 예측 가능: {resource_name}")
                details.append(f"  ✗ {resource_name}: ID {accessible_ids} 접근 가능")
                result['status'] = 'VULNERABLE'

        except:
            pass

    if not sequential_ids_found:
        details.append("  ✓ 순차적 ID 패턴 발견 안 됨")

    # 2. 인증 없이 객체 접근
    details.append("\n[IDOR-2] 인증 없이 객체 접근")

    unauthenticated_access = False

    for endpoint_pattern, resource_name in id_based_endpoints:
        try:
            url = f"{target_url}{endpoint_pattern.format(id=1)}"

            # 인증 헤더 없이 요청
            resp = requests.get(url, timeout=3)

            if resp.status_code == 200:
                unauthenticated_access = True
                result['vulnerabilities'].append(f"인증 없이 접근 가능: {resource_name}")
                details.append(f"  ✗ {resource_name} (ID=1): 인증 없이 접근 가능")
                result['status'] = 'VULNERABLE'
            elif resp.status_code == 401:
                details.append(f"  ✓ {resource_name}: 인증 필요 (401)")
            elif resp.status_code == 403:
                details.append(f"  ✓ {resource_name}: 권한 필요 (403)")

        except:
            pass

    # 3. 다른 사용자 데이터 접근 시도 (시뮬레이션)
    details.append("\n[IDOR-3] 권한 검증 테스트")

    try:
        # 사용자 A의 토큰으로 사용자 B의 데이터 접근 시도
        # 실제로는 두 개의 계정이 필요하지만, 여기서는 패턴만 확인

        test_cases = [
            ("/api/employees/1", "다른 직원 정보"),
            ("/api/employees/2", "다른 직원 정보"),
            ("/api/boards/1", "다른 사용자 게시글"),
            ("/api/files/1", "다른 사용자 파일"),
            ("/api/approvals/1", "다른 사용자 결재"),
        ]

        for endpoint, description in test_cases:
            try:
                url = f"{target_url}{endpoint}"

                # Authorization 헤더 없이 요청
                resp = requests.get(url, timeout=3)

                if resp.status_code == 200:
                    # 응답에 민감 정보가 있는지 확인
                    if len(resp.text) > 100:  # 실제 데이터가 있음
                        result['vulnerabilities'].append(f"권한 없이 접근: {description}")
                        details.append(f"  ✗ {endpoint}: 권한 검증 없음")
                        result['status'] = 'VULNERABLE'

            except:
                pass

    except:
        details.append("  • 권한 검증 테스트 실패")

    # 4. HTTP 메서드 변경 우회
    details.append("\n[IDOR-4] HTTP 메서드 변경 우회")

    try:
        # GET이 차단되어도 HEAD, OPTIONS로 우회 가능한지
        test_endpoint = f"{target_url}/api/employees/1"

        methods = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'DELETE']
        accessible_methods = []

        for method in methods:
            try:
                resp = requests.request(method, test_endpoint, timeout=3)

                if resp.status_code in [200, 201, 204]:
                    accessible_methods.append(method)
            except:
                pass

        if len(accessible_methods) > 1:
            result['vulnerabilities'].append(f"다양한 메서드로 접근 가능: {accessible_methods}")
            details.append(f"  ⚠ 접근 가능 메서드: {', '.join(accessible_methods)}")

    except:
        details.append("  • HTTP 메서드 테스트 실패")

    # 5. ID 조작을 통한 권한 상승
    details.append("\n[IDOR-5] ID 조작 권한 상승")

    try:
        # 일반 사용자 → 관리자 계정 접근 시도
        admin_ids = [0, 1, 'admin', 'root', 'administrator']

        for admin_id in admin_ids:
            try:
                url = f"{target_url}/api/employees/{admin_id}"
                resp = requests.get(url, timeout=3)

                if resp.status_code == 200:
                    # role이 ADMIN인지 확인
                    if 'ADMIN' in resp.text or 'admin' in resp.text.lower():
                        result['vulnerabilities'].append(f"관리자 정보 접근 가능: ID={admin_id}")
                        details.append(f"  ✗ 관리자 계정 조회 가능: {admin_id}")
                        result['status'] = 'VULNERABLE'
            except:
                pass

    except:
        details.append("  • 권한 상승 테스트 실패")

    # 6. 파라미터 조작
    details.append("\n[IDOR-6] 파라미터 조작")

    try:
        # user_id, employee_id 파라미터 조작
        param_tests = [
            ("/api/approvals/my", {"employee_id": "1"}, "다른 직원 결재 조회"),
            ("/api/approvals/my", {"employee_id": "999"}, "존재하지 않는 직원"),
            ("/api/attendance/my", {"employee_id": "1"}, "다른 직원 근태"),
        ]

        for endpoint, params, description in param_tests:
            try:
                url = f"{target_url}{endpoint}"
                resp = requests.get(url, params=params, timeout=3)

                if resp.status_code == 200 and len(resp.text) > 100:
                    result['vulnerabilities'].append(f"파라미터 조작 가능: {description}")
                    details.append(f"  ✗ {endpoint}: {description}")
                    result['status'] = 'VULNERABLE'
            except:
                pass

    except:
        details.append("  • 파라미터 조작 테스트 실패")

    # 7. UUID vs Sequential ID
    details.append("\n[IDOR-7] ID 형식 분석")

    try:
        # ID가 UUID인지 순차 숫자인지 확인
        url = f"{target_url}/api/boards"
        resp = requests.get(url, timeout=5)

        if resp.status_code == 200:
            import re
            # UUID 패턴 찾기
            uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
            uuids_found = re.findall(uuid_pattern, resp.text, re.IGNORECASE)

            # 숫자 ID 찾기
            numeric_id_pattern = r'"id"\s*:\s*(\d+)'
            numeric_ids = re.findall(numeric_id_pattern, resp.text)

            if numeric_ids and not uuids_found:
                result['vulnerabilities'].append("순차적 숫자 ID 사용")
                details.append(f"  ⚠ 순차적 숫자 ID 사용 (예측 가능)")
                details.append(f"     권장: UUID 또는 비예측 가능한 ID 사용")
                result['status'] = 'VULNERABLE'
            elif uuids_found:
                details.append(f"  ✓ UUID 사용 (예측 불가능)")

    except:
        details.append("  • ID 형식 분석 실패")

    if result['status'] == 'SAFE':
        details.append("\n✓ IDOR 방어가 적절히 구현되어 있습니다")

    result['details'] = '\n'.join(details)
    return result
