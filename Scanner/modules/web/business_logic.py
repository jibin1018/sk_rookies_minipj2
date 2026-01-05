"""
Business Logic Vulnerabilities Scanner
비즈니스 로직 취약점 탐지
"""
import requests
import time

def scan(target_url):
    result = {
        'name': 'Business Logic Vulnerabilities',
        'category': 'Business Logic',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '비즈니스 로직 검증, 상태 전이 제어, 동시성 제어, 입력 값 범위 검증',
        'details': ''
    }

    details = []

    # 1. 결재 프로세스 우회
    details.append("[Business Logic-1] 결재 프로세스 검증")

    try:
        # 결재 생성
        approval_url = f"{target_url}/api/approvals"

        approval_data = {
            "title": "Test Approval",
            "content": "Test",
            "type": "VACATION"
        }

        resp = requests.post(approval_url, json=approval_data, timeout=5)

        if resp.status_code in [200, 201]:
            details.append(f"  • 결재 생성 가능")

            # 결재 ID 추출 시도
            try:
                approval_id = resp.json().get('id', 1)

                # 결재선 없이 직접 승인 시도
                approve_url = f"{target_url}/api/approvals/{approval_id}/approve"
                approve_resp = requests.post(approve_url, timeout=5)

                if approve_resp.status_code == 200:
                    result['vulnerabilities'].append("결재선 없이 승인 가능")
                    details.append(f"  ✗ 결재선 건너뛰고 직접 승인됨")
                    result['status'] = 'VULNERABLE'
                else:
                    details.append(f"  ✓ 결재선 검증됨")

            except:
                details.append(f"  • 결재 ID 추출 실패")

    except:
        details.append(f"  • 결재 테스트 실패")

    # 2. 근태 조작
    details.append("\n[Business Logic-2] 근태 관리 검증")

    try:
        # 출근 없이 퇴근 시도
        checkout_url = f"{target_url}/api/attendance/check-out"

        resp = requests.post(checkout_url, json={}, timeout=5)

        if resp.status_code == 200:
            result['vulnerabilities'].append("출근 없이 퇴근 가능")
            details.append(f"  ✗ 출근 기록 없이 퇴근 처리됨")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ 출근 여부 검증됨")

        # 중복 출근 시도
        checkin_url = f"{target_url}/api/attendance/check-in"

        for i in range(3):
            resp = requests.post(checkin_url, json={}, timeout=5)

            if i > 0 and resp.status_code == 200:
                result['vulnerabilities'].append("중복 출근 가능")
                details.append(f"  ✗ 중복 출근 처리됨")
                result['status'] = 'VULNERABLE'
                break

    except:
        details.append(f"  • 근태 테스트 실패")

    # 3. 음수 값 입력
    details.append("\n[Business Logic-3] 음수/특수 값 검증")

    try:
        # 음수 파일 크기
        test_cases = [
            ("/api/boards", {"title": "Test", "content": "A" * -1}, "음수 길이"),
            ("/api/employees", {"employeeId": "test", "salary": -1000}, "음수 급여"),
        ]

        for endpoint, data, description in test_cases:
            try:
                url = f"{target_url}{endpoint}"
                resp = requests.post(url, json=data, timeout=5)

                if resp.status_code in [200, 201]:
                    result['vulnerabilities'].append(f"음수 값 허용: {description}")
                    details.append(f"  ✗ {description} 입력 허용됨")
                    result['status'] = 'VULNERABLE'

            except:
                pass

    except:
        details.append(f"  • 음수 값 테스트 실패")

    # 4. Race Condition (동시성 제어)
    details.append("\n[Business Logic-4] Race Condition 테스트")

    try:
        # 동일한 결재를 동시에 승인 시도
        approval_id = 1
        approve_url = f"{target_url}/api/approvals/{approval_id}/approve"

        import threading

        results_race = []

        def concurrent_approve():
            try:
                resp = requests.post(approve_url, timeout=5)
                results_race.append(resp.status_code)
            except:
                pass

        threads = []
        for _ in range(5):
            t = threading.Thread(target=concurrent_approve)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # 여러 번 성공하면 Race Condition 존재
        success_count = sum(1 for code in results_race if code == 200)

        if success_count > 1:
            result['vulnerabilities'].append("Race Condition: 중복 승인")
            details.append(f"  ✗ 동시 승인 {success_count}회 성공")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ 동시성 제어됨")

    except:
        details.append(f"  • Race Condition 테스트 실패")

    # 5. 상태 전이 무시
    details.append("\n[Business Logic-5] 상태 전이 검증")

    try:
        # 결재 상태를 PENDING → APPROVED로 직접 변경 시도 (REVIEWING 건너뛰기)
        approval_url = f"{target_url}/api/approvals/1"

        # 상태를 직접 APPROVED로 변경 시도
        patch_data = {
            "status": "APPROVED"
        }

        resp = requests.patch(approval_url, json=patch_data, timeout=5)

        if resp.status_code == 200:
            result['vulnerabilities'].append("상태 전이 검증 없음")
            details.append(f"  ✗ 중간 상태 건너뛰고 변경 가능")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ 상태 전이 제어됨")

    except:
        details.append(f"  • 상태 전이 테스트 실패")

    # 6. 시간 조작
    details.append("\n[Business Logic-6] 시간/날짜 조작")

    try:
        # 과거 날짜로 출근 시도
        checkin_url = f"{target_url}/api/attendance/check-in"

        past_date_data = {
            "date": "2020-01-01",
            "time": "09:00:00"
        }

        resp = requests.post(checkin_url, json=past_date_data, timeout=5)

        if resp.status_code == 200:
            result['vulnerabilities'].append("과거 날짜 입력 가능")
            details.append(f"  ✗ 과거 날짜로 근태 입력 가능")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ 날짜 검증됨")

        # 미래 날짜로 휴가 신청
        leave_url = f"{target_url}/api/approvals"

        future_leave_data = {
            "type": "VACATION",
            "startDate": "2030-12-31",
            "endDate": "2031-01-01"
        }

        resp = requests.post(leave_url, json=future_leave_data, timeout=5)

        if resp.status_code in [200, 201]:
            details.append(f"  • 미래 날짜 휴가 신청 가능")

    except:
        details.append(f"  • 시간 조작 테스트 실패")

    # 7. 수량 조작
    details.append("\n[Business Logic-7] 수량/범위 검증")

    try:
        # 0 또는 음수 수량
        test_cases = [
            (0, "0개"),
            (-1, "음수"),
            (9999999, "과도한 수량"),
        ]

        for quantity, description in test_cases:
            # 파일 다운로드 횟수 조작 등
            download_url = f"{target_url}/api/files/1"

            for _ in range(abs(quantity)):
                try:
                    resp = requests.get(download_url, timeout=2)
                    if resp.status_code != 200:
                        break
                except:
                    break

    except:
        details.append(f"  • 수량 테스트 실패")

    # 8. 권한 없는 작업 수행
    details.append("\n[Business Logic-8] 권한 검증")

    try:
        # 일반 사용자가 직원 삭제 시도
        delete_url = f"{target_url}/api/employees/1"

        resp = requests.delete(delete_url, timeout=5)

        if resp.status_code == 200:
            result['vulnerabilities'].append("권한 없이 삭제 가능")
            details.append(f"  ✗ 인증 없이 직원 삭제 가능")
            result['status'] = 'VULNERABLE'
        elif resp.status_code == 401:
            details.append(f"  ✓ 인증 필요 (401)")
        elif resp.status_code == 403:
            details.append(f"  ✓ 권한 필요 (403)")

    except:
        details.append(f"  • 권한 테스트 실패")

    # 9. 논리적 순서 무시
    details.append("\n[Business Logic-9] 작업 순서 검증")

    try:
        # 결재 생성 전에 결재선 추가 시도
        approval_line_url = f"{target_url}/api/approvals/99999/approval-line"

        line_data = {
            "approverId": 1,
            "order": 1
        }

        resp = requests.post(approval_line_url, json=line_data, timeout=5)

        if resp.status_code == 200:
            result['vulnerabilities'].append("작업 순서 검증 없음")
            details.append(f"  ✗ 결재 없이 결재선 추가 가능")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ 작업 순서 검증됨")

    except:
        details.append(f"  • 작업 순서 테스트 실패")

    # 10. 필수 필드 누락
    details.append("\n[Business Logic-10] 필수 필드 검증")

    try:
        # 필수 필드 없이 게시글 생성
        board_url = f"{target_url}/api/boards"

        incomplete_data = {
            # title 누락
            "content": "Test content"
        }

        resp = requests.post(board_url, json=incomplete_data, timeout=5)

        if resp.status_code in [200, 201]:
            result['vulnerabilities'].append("필수 필드 검증 없음")
            details.append(f"  ✗ title 없이 게시글 생성됨")
            result['status'] = 'VULNERABLE'
        elif resp.status_code == 400:
            details.append(f"  ✓ 필수 필드 검증됨 (400)")

    except:
        details.append(f"  • 필수 필드 테스트 실패")

    if result['status'] == 'SAFE':
        details.append("\n✓ 비즈니스 로직이 적절히 검증되고 있습니다")

    result['details'] = '\n'.join(details)
    return result
