"""
Security Headers Scanner
HTTP 보안 헤더 검증 및 누락 확인
"""
import requests

def scan(target_url):
    result = {
        'name': 'Security Headers',
        'category': 'Configuration',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': '모든 필수 보안 헤더를 설정하여 공격 표면 축소',
        'details': ''
    }

    details = []

    # 필수 보안 헤더 목록
    security_headers = {
        'Strict-Transport-Security': {
            'description': 'HSTS - HTTPS 강제',
            'severity': 'HIGH',
            'recommendation': 'Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        'X-Frame-Options': {
            'description': 'Clickjacking 방지',
            'severity': 'MEDIUM',
            'recommendation': 'X-Frame-Options: DENY 또는 SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'description': 'MIME 타입 스니핑 방지',
            'severity': 'MEDIUM',
            'recommendation': 'X-Content-Type-Options: nosniff'
        },
        'Content-Security-Policy': {
            'description': 'XSS/데이터 주입 방지',
            'severity': 'HIGH',
            'recommendation': "Content-Security-Policy: default-src 'self'"
        },
        'X-XSS-Protection': {
            'description': 'XSS 필터 (레거시)',
            'severity': 'LOW',
            'recommendation': 'X-XSS-Protection: 1; mode=block'
        },
        'Referrer-Policy': {
            'description': 'Referrer 정보 제어',
            'severity': 'LOW',
            'recommendation': 'Referrer-Policy: strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'description': '브라우저 기능 제어',
            'severity': 'LOW',
            'recommendation': 'Permissions-Policy: geolocation=(), microphone=()'
        }
    }

    details.append("[보안 헤더 검증]")

    try:
        # HTTP 헤더 확인
        resp = requests.get(target_url, timeout=5, allow_redirects=True)
        headers = resp.headers

        # 각 보안 헤더 확인
        missing_headers = []
        weak_headers = []

        for header_name, header_info in security_headers.items():
            if header_name not in headers:
                missing_headers.append(header_name)
                result['vulnerabilities'].append(f"{header_name} 헤더 누락")
                details.append(f"  ✗ {header_name}: 미설정")
                details.append(f"     - {header_info['description']}")
                details.append(f"     - 권장: {header_info['recommendation']}")

                # 심각도에 따라 상태 업데이트
                if header_info['severity'] == 'HIGH':
                    result['status'] = 'VULNERABLE'
                    if result['severity'] != 'HIGH' and result['severity'] != 'CRITICAL':
                        result['severity'] = 'HIGH'
                elif header_info['severity'] == 'MEDIUM' and result['status'] == 'SAFE':
                    result['status'] = 'VULNERABLE'
            else:
                header_value = headers[header_name]
                details.append(f"  ✓ {header_name}: {header_value}")

                # 헤더 값 검증
                if header_name == 'X-XSS-Protection' and header_value == '0':
                    weak_headers.append(f"{header_name}: {header_value}")
                    result['vulnerabilities'].append("X-XSS-Protection이 비활성화됨")
                    details.append(f"     ⚠ XSS Protection 비활성화")
                    result['status'] = 'VULNERABLE'

                if header_name == 'Content-Security-Policy':
                    # 약한 CSP 정책 확인
                    if 'unsafe-inline' in header_value:
                        weak_headers.append(f"CSP: unsafe-inline 허용")
                        result['vulnerabilities'].append("CSP에서 unsafe-inline 허용")
                        details.append(f"     ⚠ unsafe-inline 허용 (인라인 스크립트 실행 가능)")
                        result['status'] = 'VULNERABLE'
                    if 'unsafe-eval' in header_value:
                        weak_headers.append(f"CSP: unsafe-eval 허용")
                        result['vulnerabilities'].append("CSP에서 unsafe-eval 허용")
                        details.append(f"     ⚠ unsafe-eval 허용 (eval() 실행 가능)")
                        result['status'] = 'VULNERABLE'
                    if " * " in header_value or header_value.endswith("*"):
                        weak_headers.append(f"CSP: 모든 소스 허용")
                        result['vulnerabilities'].append("CSP에서 모든 소스(*) 허용")
                        details.append(f"     ⚠ 모든 소스 허용")
                        result['status'] = 'VULNERABLE'

                if header_name == 'X-Frame-Options':
                    if header_value.upper() not in ['DENY', 'SAMEORIGIN']:
                        weak_headers.append(f"X-Frame-Options: {header_value}")
                        result['vulnerabilities'].append("X-Frame-Options 값이 약함")
                        details.append(f"     ⚠ 권장 값: DENY 또는 SAMEORIGIN")

        # Server 헤더 정보 노출 확인
        details.append("\n[서버 정보 노출]")
        if 'Server' in headers:
            server_value = headers['Server']
            details.append(f"  ⚠ Server 헤더 노출: {server_value}")
            result['vulnerabilities'].append(f"서버 정보 노출: {server_value}")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ Server 헤더 숨김")

        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            details.append(f"  ⚠ X-Powered-By 헤더 노출: {powered_by}")
            result['vulnerabilities'].append(f"기술 스택 노출: {powered_by}")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ X-Powered-By 헤더 숨김")

        # CORS 헤더 확인
        details.append("\n[CORS 설정]")
        if 'Access-Control-Allow-Origin' in headers:
            cors_value = headers['Access-Control-Allow-Origin']
            details.append(f"  • Access-Control-Allow-Origin: {cors_value}")

            if cors_value == '*':
                result['vulnerabilities'].append("CORS: 모든 출처 허용 (*)")
                details.append(f"     ⚠ 모든 출처 허용 - 제한 권장")
                result['status'] = 'VULNERABLE'

        # 요약
        details.append(f"\n[요약]")
        details.append(f"  • 전체 보안 헤더: {len(security_headers)}개")
        details.append(f"  • 누락된 헤더: {len(missing_headers)}개")
        details.append(f"  • 약한 헤더: {len(weak_headers)}개")

        if result['status'] == 'SAFE':
            details.append("\n✓ 보안 헤더가 적절히 설정되어 있습니다")

    except requests.exceptions.RequestException as e:
        result['status'] = 'ERROR'
        result['vulnerabilities'].append(f"요청 실패: {str(e)}")
        details.append(f"✗ 요청 실패: {str(e)}")
    except Exception as e:
        result['status'] = 'ERROR'
        result['vulnerabilities'].append(f"오류 발생: {str(e)}")
        details.append(f"✗ 오류: {str(e)}")

    result['details'] = '\n'.join(details)
    return result
