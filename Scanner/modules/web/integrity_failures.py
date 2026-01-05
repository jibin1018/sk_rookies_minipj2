"""
A08: Software and Data Integrity Failures
소프트웨어 및 데이터 무결성 실패
"""
import requests
import hashlib
import base64
import re

def scan(target_url):
    result = {
        'name': 'A08: Software and Data Integrity Failures',
        'category': 'OWASP TOP 10 2025',
        'status': 'SAFE',
        'severity': 'MEDIUM',
        'vulnerabilities': [],
        'recommendation': 'SRI 태그 사용, 디지털 서명 검증, 무결성 검사 구현, 안전한 역직렬화',
        'details': ''
    }
    
    details = []
    
    # 1. Subresource Integrity (SRI) 확인
    details.append("[무결성-1] Subresource Integrity (SRI) 확인")
    
    try:
        resp = requests.get(target_url, timeout=5)
        html = resp.text
        
        # script 태그 찾기
        script_tags = re.findall(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        link_tags = re.findall(r'<link[^>]*href=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        
        sri_count = 0
        no_sri_count = 0
        external_resources = []
        
        # 외부 스크립트 확인
        for script_src in script_tags:
            # 외부 CDN 스크립트인지 확인
            if any(cdn in script_src for cdn in ['cdn.', 'unpkg.', 'jsdelivr.', 'cloudflare.', 'ajax.googleapis']):
                external_resources.append(('script', script_src))
                
                # SRI 체크
                script_tag_full = re.search(
                    rf'<script[^>]*src=["\'].*?{re.escape(script_src)}.*?["\'][^>]*>',
                    html,
                    re.IGNORECASE
                )
                
                if script_tag_full:
                    if 'integrity=' in script_tag_full.group(0):
                        sri_count += 1
                        details.append(f"  ✓ SRI: {script_src[:50]}...")
                    else:
                        no_sri_count += 1
                        details.append(f"  ✗ SRI 없음: {script_src[:50]}...")
        
        # 외부 CSS 확인
        for link_href in link_tags:
            if any(cdn in link_href for cdn in ['cdn.', 'unpkg.', 'jsdelivr.', 'cloudflare.']) and '.css' in link_href:
                external_resources.append(('link', link_href))
                
                link_tag_full = re.search(
                    rf'<link[^>]*href=["\'].*?{re.escape(link_href)}.*?["\'][^>]*>',
                    html,
                    re.IGNORECASE
                )
                
                if link_tag_full:
                    if 'integrity=' in link_tag_full.group(0):
                        sri_count += 1
                    else:
                        no_sri_count += 1
                        details.append(f"  ✗ CSS SRI 없음: {link_href[:50]}...")
        
        if no_sri_count > 0:
            result['vulnerabilities'].append(f"SRI 미적용 외부 리소스: {no_sri_count}개")
            result['status'] = 'VULNERABLE'
        elif sri_count > 0:
            details.append(f"\n  총 {sri_count}개 리소스에 SRI 적용됨")
        else:
            details.append("  • 외부 CDN 리소스 없음")
            
    except Exception as e:
        details.append(f"  • SRI 확인 실패: {str(e)[:50]}")
    
    # 2. 안전하지 않은 역직렬화
    details.append("\n[무결성-2] 안전하지 않은 역직렬화 확인")
    
    try:
        # Java 직렬화 매직 바이트
        java_serialized = base64.b64encode(b'\xac\xed\x00\x05').decode()
        
        # 쿠키에 직렬화 데이터 전송
        cookies = {'session': java_serialized, 'user_data': java_serialized}
        headers = {'X-Security-Mode': 'vulnerable'}
        
        resp = requests.get(f"{target_url}/api/employees/me", 
                           cookies=cookies, headers=headers, timeout=5)
        
        # 역직렬화 에러 확인
        error_indicators = [
            'java.io.ObjectInputStream',
            'InvalidClassException',
            'StreamCorruptedException',
            'pickle',
            'unserialize',
            '__wakeup',
            '__destruct'
        ]
        
        if any(indicator in resp.text for indicator in error_indicators):
            result['vulnerabilities'].append("역직렬화 처리 감지")
            details.append("  ✗ 취약: 직렬화 데이터 처리 중")
            result['status'] = 'VULNERABLE'
        else:
            details.append("  ✓ 양호: 역직렬화 에러 없음")
            
    except:
        details.append("  • 역직렬화 테스트 실패")
    
    # 3. CI/CD 파이프라인 노출
    details.append("\n[무결성-3] CI/CD 설정 파일 노출 확인")
    
    cicd_files = [
        ('/.github/workflows', 'GitHub Actions'),
        ('/.gitlab-ci.yml', 'GitLab CI'),
        ('/Jenkinsfile', 'Jenkins'),
        ('/.circleci/config.yml', 'CircleCI'),
        ('/azure-pipelines.yml', 'Azure Pipelines'),
        ('/.travis.yml', 'Travis CI'),
        ('/bitbucket-pipelines.yml', 'Bitbucket Pipelines'),
        ('/.drone.yml', 'Drone CI'),
    ]
    
    exposed_files = []
    
    for file_path, ci_name in cicd_files:
        try:
            resp = requests.get(f"{target_url}{file_path}", timeout=5)
            
            if resp.status_code == 200 and len(resp.text) > 0:
                exposed_files.append(ci_name)
                result['vulnerabilities'].append(f"CI/CD 설정 노출: {ci_name}")
                details.append(f"  ✗ 취약: {file_path} 접근 가능")
                result['status'] = 'VULNERABLE'
                
        except:
            pass
    
    if not exposed_files:
        details.append("  ✓ 양호: CI/CD 파일 노출 없음")
    
    # 4. 업데이트 메커니즘 보안
    details.append("\n[무결성-4] 자동 업데이트 보안 확인")
    
    try:
        update_endpoints = [
            '/api/update',
            '/api/version',
            '/api/check-updates',
            '/updates/check',
        ]
        
        for endpoint in update_endpoints:
            try:
                resp = requests.get(f"{target_url}{endpoint}", timeout=5)
                
                if resp.status_code == 200:
                    # 서명 검증 여부 확인
                    security_fields = ['signature', 'checksum', 'sha256', 'sha512', 'hash', 'verify']
                    
                    has_integrity = any(field in resp.text.lower() for field in security_fields)
                    
                    if not has_integrity:
                        result['vulnerabilities'].append("업데이트 무결성 검증 부재")
                        details.append(f"  ⚠ 주의: {endpoint} - 서명/체크섬 없음")
                        result['status'] = 'VULNERABLE'
                    else:
                        details.append(f"  ✓ {endpoint} - 무결성 검증 필드 존재")
                    break
                    
            except:
                pass
                
    except:
        details.append("  • 업데이트 기능 없음")
    
    # 5. 코드 서명 확인
    details.append("\n[무결성-5] 다운로드 가능한 파일 무결성")
    
    try:
        download_endpoints = [
            '/downloads',
            '/download',
            '/files',
            '/releases',
        ]
        
        for endpoint in download_endpoints:
            try:
                resp = requests.get(f"{target_url}{endpoint}", timeout=5)
                
                if resp.status_code == 200:
                    html = resp.text
                    
                    # SHA256, MD5 체크섬 확인
                    checksum_indicators = [
                        'sha256', 'sha-256', 'sha512', 'sha-512',
                        'md5', 'checksum', 'hash', 'integrity',
                        '.sha256', '.md5', '.asc'  # 파일 확장자
                    ]
                    
                    has_checksum = any(indicator in html.lower() for indicator in checksum_indicators)
                    
                    if has_checksum:
                        details.append(f"  ✓ 양호: {endpoint} - 체크섬 제공됨")
                    else:
                        result['vulnerabilities'].append("다운로드 파일 체크섬 미제공")
                        details.append(f"  ⚠ 주의: {endpoint} - 파일 무결성 검증 수단 없음")
                    break
                    
            except:
                pass
                
    except:
        details.append("  • 다운로드 기능 없음")
    
    # 6. npm/yarn 잠금 파일 노출
    details.append("\n[무결성-6] 의존성 잠금 파일 확인")
    
    lock_files = [
        ('/package-lock.json', 'npm'),
        ('/yarn.lock', 'Yarn'),
        ('/composer.lock', 'Composer'),
        ('/Gemfile.lock', 'Bundler'),
        ('/Pipfile.lock', 'Pipenv'),
        ('/poetry.lock', 'Poetry'),
        ('/pnpm-lock.yaml', 'pnpm'),
    ]
    
    for lock_file, tool_name in lock_files:
        try:
            resp = requests.get(f"{target_url}{lock_file}", timeout=5)
            
            if resp.status_code == 200 and len(resp.text) > 100:
                result['vulnerabilities'].append(f"의존성 잠금 파일 노출: {tool_name}")
                details.append(f"  ⚠ 정보 노출: {lock_file}")
                
        except:
            pass
    
    # 7. 서명되지 않은 쿠키/토큰
    details.append("\n[무결성-7] 쿠키/토큰 서명 확인")
    
    try:
        resp = requests.get(target_url, timeout=5)
        
        if 'Set-Cookie' in resp.headers:
            cookies = resp.headers['Set-Cookie']
            
            # JWT 토큰 확인
            jwt_pattern = r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.([A-Za-z0-9-_]+)?'
            jwt_match = re.search(jwt_pattern, cookies)
            
            if jwt_match:
                jwt_token = jwt_match.group(0)
                parts = jwt_token.split('.')
                
                if len(parts) == 3:
                    if not parts[2] or parts[2] == '':
                        result['vulnerabilities'].append("서명되지 않은 JWT (alg: none)")
                        details.append("  ✗ JWT 서명 없음")
                        result['status'] = 'VULNERABLE'
                    else:
                        details.append("  ✓ JWT 서명 존재")
            
            # 일반 세션 쿠키
            if 'session=' in cookies:
                # Base64로 디코딩 가능한지 확인 (서명 없는 세션)
                session_match = re.search(r'session=([^;]+)', cookies)
                if session_match:
                    session_value = session_match.group(1)
                    
                    try:
                        decoded = base64.b64decode(session_value)
                        # JSON이나 직렬화된 데이터라면 서명 없음
                        if b'{' in decoded or b'user' in decoded.lower():
                            result['vulnerabilities'].append("서명되지 않은 세션 쿠키")
                            details.append("  ⚠ 세션 쿠키 서명 없음 (조작 가능)")
                            result['status'] = 'VULNERABLE'
                    except:
                        pass
                        
    except:
        details.append("  • 쿠키 확인 실패")
    
    # 8. Docker/Kubernetes 설정 노출
    details.append("\n[무결성-8] 컨테이너 설정 파일 노출")
    
    container_files = [
        '/Dockerfile',
        '/docker-compose.yml',
        '/docker-compose.yaml',
        '/.dockerignore',
        '/kubernetes.yml',
        '/k8s.yaml',
        '/.helm',
    ]
    
    for file_path in container_files:
        try:
            resp = requests.get(f"{target_url}{file_path}", timeout=5)
            
            if resp.status_code == 200 and len(resp.text) > 0:
                result['vulnerabilities'].append(f"컨테이너 설정 노출: {file_path}")
                details.append(f"  ⚠ {file_path} 접근 가능")
                
        except:
            pass
    
    # 9. 소스맵 파일 노출
    details.append("\n[무결성-9] 소스맵 파일 노출")
    
    try:
        # JavaScript 소스맵
        sourcemap_patterns = [
            '/static/js/main.*.js.map',
            '/js/app.js.map',
            '/bundle.js.map',
        ]
        
        # 메인 페이지에서 JS 파일 찾기
        resp = requests.get(target_url, timeout=5)
        js_files = re.findall(r'src=["\']([^"\']*\.js)["\']', resp.text)
        
        for js_file in js_files:
            map_file = js_file + '.map'
            
            try:
                map_resp = requests.get(f"{target_url}{map_file}", timeout=5)
                
                if map_resp.status_code == 200:
                    result['vulnerabilities'].append(f"소스맵 노출: {map_file}")
                    details.append(f"  ⚠ {map_file} 접근 가능 (소스 코드 유출)")
                    result['status'] = 'VULNERABLE'
                    break
                    
            except:
                pass
                
    except:
        details.append("  • 소스맵 확인 실패")
    
    # 10. Git 저장소 노출
    details.append("\n[무결성-10] Git 저장소 노출")
    
    try:
        git_files = ['/.git/HEAD', '/.git/config', '/.git/index']
        
        for git_file in git_files:
            resp = requests.get(f"{target_url}{git_file}", timeout=5)
            
            if resp.status_code == 200:
                result['vulnerabilities'].append("Git 저장소 노출")
                details.append(f"  ✗ 취약: {git_file} 접근 가능")
                result['status'] = 'VULNERABLE'
                break
                
    except:
        pass
    
    result['details'] = '\n'.join(details)
    return result