"""
Rate Limiting Scanner
무제한 요청, Brute Force 방어 검증
"""
import requests
import time

def scan(target_url):
    result = {
        'name': 'Rate Limiting & Brute Force Protection',
        'category': 'Authentication',
        'status': 'SAFE',
        'severity': 'HIGH',
        'vulnerabilities': [],
        'recommendation': 'Rate Limiting 구현, 계정 잠금 정책, CAPTCHA 도입',
        'details': ''
    }

    details = []

    # 1. 로그인 엔드포인트 Brute Force 테스트
    details.append("[Rate Limit-1] 로그인 Brute Force 방어")

    login_url = f"{target_url}/api/auth/login"
    brute_force_attempts = 20  # 20회 시도

    try:
        success_count = 0
        failed_count = 0
        blocked_count = 0

        start_time = time.time()

        for i in range(brute_force_attempts):
            try:
                login_data = {
                    "employeeId": "test_user",
                    "password": f"wrong_password_{i}"
                }

                resp = requests.post(login_url, json=login_data, timeout=5)

                if resp.status_code == 200:
                    success_count += 1
                elif resp.status_code == 401 or resp.status_code == 400:
                    failed_count += 1
                elif resp.status_code == 429:  # Too Many Requests
                    blocked_count += 1
                    details.append(f"  ✓ {i+1}번째 시도에서 Rate Limit 적용됨 (429)")
                    break
                elif resp.status_code == 403:  # Forbidden
                    blocked_count += 1
                    details.append(f"  ✓ {i+1}번째 시도에서 차단됨 (403)")
                    break

                # 약간의 딜레이
                time.sleep(0.1)

            except:
                pass

        end_time = time.time()
        duration = end_time - start_time

        details.append(f"  • 총 시도: {brute_force_attempts}회")
        details.append(f"  • 실패 응답: {failed_count}회")
        details.append(f"  • 차단: {blocked_count}회")
        details.append(f"  • 소요 시간: {duration:.2f}초")

        if blocked_count == 0:
            result['vulnerabilities'].append("로그인 Rate Limiting 없음")
            details.append(f"  ✗ Brute Force 방어 없음 ({brute_force_attempts}회 무제한 시도 가능)")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ Rate Limiting 작동")

    except Exception as e:
        details.append(f"  • 테스트 실패: {str(e)}")

    # 2. API 엔드포인트 Rate Limiting
    details.append("\n[Rate Limit-2] API 엔드포인트 Rate Limiting")

    api_endpoints = [
        "/api/boards",
        "/api/employees",
        "/api/departments",
    ]

    for endpoint in api_endpoints:
        try:
            url = f"{target_url}{endpoint}"
            rapid_requests = 50

            blocked = False
            for i in range(rapid_requests):
                resp = requests.get(url, timeout=2)

                if resp.status_code == 429:
                    details.append(f"  ✓ {endpoint}: {i+1}회 후 Rate Limit")
                    blocked = True
                    break

            if not blocked:
                result['vulnerabilities'].append(f"API Rate Limiting 없음: {endpoint}")
                details.append(f"  ✗ {endpoint}: {rapid_requests}회 무제한 요청 가능")
                result['status'] = 'VULNERABLE'

        except:
            pass

    # 3. 계정 잠금 정책
    details.append("\n[Rate Limit-3] 계정 잠금 정책")

    try:
        login_url = f"{target_url}/api/auth/login"

        # 같은 계정으로 연속 실패 시도
        failed_login_attempts = 10

        for i in range(failed_login_attempts):
            login_data = {
                "employeeId": "lock_test_user",
                "password": "wrong_password"
            }

            resp = requests.post(login_url, json=login_data, timeout=5)

            if resp.status_code == 423:  # Locked
                details.append(f"  ✓ {i+1}회 실패 후 계정 잠금됨 (423)")
                break
            elif resp.status_code == 429:
                details.append(f"  ✓ {i+1}회 실패 후 Rate Limit 적용 (429)")
                break
            elif 'locked' in resp.text.lower() or 'blocked' in resp.text.lower():
                details.append(f"  ✓ {i+1}회 실패 후 계정 잠금 메시지")
                break

            time.sleep(0.1)
        else:
            result['vulnerabilities'].append("계정 잠금 정책 없음")
            details.append(f"  ✗ {failed_login_attempts}회 실패해도 계정 잠금 안 됨")
            result['status'] = 'VULNERABLE'

    except:
        details.append(f"  • 계정 잠금 테스트 실패")

    # 4. CAPTCHA 존재 여부
    details.append("\n[Rate Limit-4] CAPTCHA 검증")

    try:
        resp = requests.get(login_url.replace('/login', ''), timeout=5)

        captcha_indicators = ['recaptcha', 'captcha', 'hcaptcha', 'g-recaptcha']
        captcha_found = False

        for indicator in captcha_indicators:
            if indicator in resp.text.lower():
                captcha_found = True
                details.append(f"  ✓ CAPTCHA 발견: {indicator}")
                break

        if not captcha_found:
            result['vulnerabilities'].append("CAPTCHA 미적용")
            details.append(f"  ⚠ CAPTCHA 없음 (자동화 공격 취약)")
            # CAPTCHA는 선택사항이므로 VULNERABLE로 변경하지 않음

    except:
        details.append(f"  • CAPTCHA 확인 실패")

    # 5. IP 기반 차단
    details.append("\n[Rate Limit-5] IP 기반 차단")

    try:
        # 동일 IP에서 대량 요청
        test_url = f"{target_url}/api/boards"
        mass_requests = 100

        blocked = False
        for i in range(mass_requests):
            resp = requests.get(test_url, timeout=2)

            if resp.status_code == 403 or resp.status_code == 429:
                details.append(f"  ✓ {i+1}회 후 IP 차단 또는 Rate Limit")
                blocked = True
                break

        if not blocked:
            result['vulnerabilities'].append("IP 기반 Rate Limiting 없음")
            details.append(f"  ✗ {mass_requests}회 요청해도 IP 차단 안 됨")
            result['status'] = 'VULNERABLE'

    except:
        details.append(f"  • IP 차단 테스트 실패")

    # 6. 비밀번호 재설정 Rate Limiting
    details.append("\n[Rate Limit-6] 비밀번호 재설정 Rate Limiting")

    password_reset_endpoints = [
        "/api/auth/reset-password",
        "/api/auth/forgot-password",
        "/api/password/reset",
    ]

    for endpoint in password_reset_endpoints:
        try:
            url = f"{target_url}{endpoint}"

            # 여러 번 요청
            for i in range(10):
                resp = requests.post(url, json={"email": "test@test.com"}, timeout=3)

                if resp.status_code == 429:
                    details.append(f"  ✓ 비밀번호 재설정: Rate Limit 적용")
                    break
            else:
                if resp.status_code not in [404]:
                    result['vulnerabilities'].append("비밀번호 재설정 Rate Limiting 없음")
                    details.append(f"  ✗ 비밀번호 재설정 무제한 요청 가능")
                    result['status'] = 'VULNERABLE'

        except:
            pass

    # 7. 회원가입 Rate Limiting
    details.append("\n[Rate Limit-7] 회원가입 Rate Limiting")

    signup_url = f"{target_url}/api/auth/signup"

    try:
        for i in range(5):
            signup_data = {
                "employeeId": f"spam_user_{i}",
                "password": "test1234",
                "name": "Spam User"
            }

            resp = requests.post(signup_url, json=signup_data, timeout=5)

            if resp.status_code == 429:
                details.append(f"  ✓ 회원가입: {i+1}회 후 Rate Limit")
                break
        else:
            result['vulnerabilities'].append("회원가입 Rate Limiting 없음")
            details.append(f"  ⚠ 회원가입 무제한 가능 (스팸 계정 생성 취약)")

    except:
        details.append(f"  • 회원가입 테스트 실패")

    if result['status'] == 'SAFE':
        details.append("\n✓ Rate Limiting이 적절히 구현되어 있습니다")

    result['details'] = '\n'.join(details)
    return result
